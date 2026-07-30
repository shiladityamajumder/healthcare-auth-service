"""File: app/core/rate_limiting.py

Purpose:
Defines replaceable rate-limit backends and the shared enforcement mechanism
used by authentication and generic API policies.

Dependency flow:
Workflow or route-policy keys and limits
-> enforce_rate_limit()
-> configured disabled, in-memory, or Redis backend
-> counter decisions
-> success or RateLimitError

This module provides a shared asynchronous rate-limiting abstraction with
three implementations:

* Disabled rate limiting for explicitly configured environments.
* In-memory fixed-window rate limiting for development and deterministic tests.
* Redis-backed fixed-window rate limiting for distributed deployments.

The Redis implementation does not create or own a Redis connection pool. It
uses the process-wide client created by ``app.db.redis_client.RedisClient``.
The application lifespan remains responsible for closing that shared client.

Authentication-specific key construction and policy selection belong in
``app.auth.workflows.rate_limits``. This module only manages counters, windows, backend
selection, and enforcement.
"""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from typing import Protocol, cast

from app.common.exceptions import (
    RateLimitBackendError,
    RateLimitError,
)
from app.core.config import (
    AppSettings,
    RateLimitBackend,
)


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Result of consuming one rate-limit attempt.

    Attributes:
        allowed: Whether the current attempt is permitted.
        remaining: Number of additional attempts permitted in the current
            window.
        retry_after_seconds: Number of seconds until the current window
            expires. Consumers should use this value when ``allowed`` is
            false.
    """

    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter(Protocol):
    """Asynchronous contract implemented by rate-limit backends."""

    async def hit(
        self,
        *,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitDecision:
        """Consume one attempt for a rate-limit key.

        Args:
            key: Stable backend key identifying the protected dimension.
            limit: Maximum attempts allowed during the window.
            window_seconds: Fixed-window duration in seconds.

        Returns:
            Decision describing whether the attempt is allowed.
        """

        ...

    async def close(self) -> None:
        """Release resources owned directly by the rate limiter."""

        ...


class _AsyncRedisClient(Protocol):
    """Minimal asynchronous Redis contract used by the limiter.

    redis-py type inference may vary between versions and editor stubs. This
    protocol isolates the limiter from the complete Redis client API while
    explicitly declaring ``eval`` as awaitable.
    """

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: str | int,
    ) -> object:
        """Execute a Redis Lua script asynchronously."""

        ...


class DisabledRateLimiter:
    """Rate limiter that permits every request.

    This backend is intended only for explicitly configured development or
    testing scenarios. Production configuration validation must prevent it
    from being selected.
    """

    async def hit(
        self,
        *,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitDecision:
        """Allow the attempt without storing any counter state."""
        _validate_hit_arguments(
            key=key,
            limit=limit,
            window_seconds=window_seconds,
        )

        return RateLimitDecision(
            allowed=True,
            remaining=max(limit - 1, 0),
            retry_after_seconds=0,
        )

    async def close(self) -> None:
        """Close the backend.

        The disabled implementation owns no resources.
        """
        return None


class InMemoryRateLimiter:
    """Single-process fixed-window rate limiter.

    This implementation is suitable for local development and deterministic
    unit tests. It is not suitable for horizontally scaled deployments because
    every process maintains an independent counter store.
    """

    _CLEANUP_INTERVAL = 256

    def __init__(self) -> None:
        """Initialize in-memory counters and concurrency protection."""
        self._entries: dict[str, tuple[int, float]] = {}
        self._lock = asyncio.Lock()
        self._operations_since_cleanup = 0
        self._closed = False

    async def hit(
        self,
        *,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitDecision:
        """Consume one attempt from an in-memory fixed window.

        Args:
            key: Stable rate-limit key.
            limit: Maximum attempts allowed during the current window.
            window_seconds: Fixed-window duration in seconds.

        Returns:
            Decision describing whether the attempt is allowed.

        Raises:
            RuntimeError: If the limiter has already been closed.
            ValueError: If the rate-limit arguments are invalid.
        """
        _validate_hit_arguments(
            key=key,
            limit=limit,
            window_seconds=window_seconds,
        )

        if self._closed:
            raise RuntimeError(
                "The in-memory rate limiter is closed."
            )

        now = time.monotonic()

        async with self._lock:
            if self._closed:
                raise RuntimeError(
                    "The in-memory rate limiter is closed."
                )

            self._operations_since_cleanup += 1

            if (
                self._operations_since_cleanup
                >= self._CLEANUP_INTERVAL
            ):
                self._remove_expired_entries(now)
                self._operations_since_cleanup = 0

            count, expires_at = self._entries.get(
                key,
                (0, now + window_seconds),
            )

            if expires_at <= now:
                count = 0
                expires_at = now + window_seconds

            count += 1

            self._entries[key] = (
                count,
                expires_at,
            )

            # Retry-After must round upward. Rounding downward could instruct
            # a client to retry before the fixed window has actually expired.
            retry_after_seconds = max(
                math.ceil(expires_at - now),
                1,
            )

            return RateLimitDecision(
                allowed=count <= limit,
                remaining=max(limit - count, 0),
                retry_after_seconds=retry_after_seconds,
            )

    def _remove_expired_entries(
        self,
        now: float,
    ) -> None:
        """Remove expired counters to limit stale memory growth.

        This method must only be called while ``self._lock`` is held.

        Args:
            now: Current monotonic timestamp.
        """
        expired_keys = [
            key
            for key, (_, expires_at) in self._entries.items()
            if expires_at <= now
        ]

        for key in expired_keys:
            self._entries.pop(key, None)

    async def close(self) -> None:
        """Clear counters and permanently close the limiter instance."""
        async with self._lock:
            if self._closed:
                return

            self._entries.clear()
            self._operations_since_cleanup = 0
            self._closed = True


class RedisRateLimiter:
    """Distributed Redis-backed fixed-window rate limiter.

    The limiter executes a Lua script that atomically:

    1. Increments the counter.
    2. Applies the fixed-window expiration.
    3. Repairs missing expiration metadata.
    4. Returns the current count and remaining TTL.

    The Redis client is injected and shared with other infrastructure. This
    class must not close it.
    """

    _SCRIPT = """
    local count = redis.call('INCR', KEYS[1])
    local ttl_ms = redis.call('PTTL', KEYS[1])

    if count == 1 or ttl_ms < 0 then
        redis.call('PEXPIRE', KEYS[1], ARGV[1])
        ttl_ms = tonumber(ARGV[1])
    end

    return {count, ttl_ms}
    """

    def __init__(
        self,
        *,
        client: object,
        key_prefix: str,
    ) -> None:
        """Initialize the limiter using a shared Redis client.

        Args:
            client: Process-wide asynchronous Redis client.
            key_prefix: Prefix applied to every rate-limit key.

        Raises:
            ValueError: If the client is missing or the prefix is blank.
        """
        if client is None:
            raise ValueError(
                "A shared Redis client is required."
            )

        normalized_prefix = key_prefix.strip().strip(":")

        if not normalized_prefix:
            raise ValueError(
                "Redis rate-limit key prefix must not be blank."
            )

        # The process-wide client originates from redis.asyncio.Redis. The
        # narrow protocol prevents incorrect synchronous type inference for
        # eval() in some editor and package-stub combinations.
        self._client = cast(
            _AsyncRedisClient,
            client,
        )
        self._key_prefix = normalized_prefix

    async def hit(
        self,
        *,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitDecision:
        """Consume one attempt through the Redis Lua script.

        Args:
            key: Stable key without the global Redis prefix.
            limit: Maximum attempts allowed during the current window.
            window_seconds: Fixed-window duration in seconds.

        Returns:
            Decision describing whether the attempt is allowed.

        Raises:
            ValueError: If the rate-limit arguments are invalid.
            RateLimitBackendError: If Redis is unavailable or returns an
                invalid response.
        """
        _validate_hit_arguments(
            key=key,
            limit=limit,
            window_seconds=window_seconds,
        )

        redis_key = f"{self._key_prefix}:{key}"
        window_milliseconds = window_seconds * 1_000

        try:
            raw_result = await self._client.eval(
                self._SCRIPT,
                1,
                redis_key,
                window_milliseconds,
            )

            count, ttl_milliseconds = self._parse_script_result(
                raw_result
            )
        except RateLimitBackendError:
            raise
        except Exception as exc:
            raise RateLimitBackendError(
                "The rate-limit service is unavailable."
            ) from exc

        retry_after_seconds = max(
            math.ceil(ttl_milliseconds / 1_000),
            1,
        )

        return RateLimitDecision(
            allowed=count <= limit,
            remaining=max(limit - count, 0),
            retry_after_seconds=retry_after_seconds,
        )

    @staticmethod
    def _parse_script_result(
        raw_result: object,
    ) -> tuple[int, int]:
        """Validate and normalize the Redis Lua response.

        Args:
            raw_result: Raw result returned by Redis ``EVAL``.

        Returns:
            Tuple containing the current count and remaining TTL in
            milliseconds.

        Raises:
            RateLimitBackendError: If Redis returns an unexpected value.
        """
        if not isinstance(raw_result, (list, tuple)):
            raise RateLimitBackendError(
                "The rate-limit service returned an invalid response."
            )

        if len(raw_result) != 2:
            raise RateLimitBackendError(
                "The rate-limit service returned an invalid response."
            )

        try:
            count = int(raw_result[0])
            ttl_milliseconds = int(raw_result[1])
        except (TypeError, ValueError) as exc:
            raise RateLimitBackendError(
                "The rate-limit service returned an invalid response."
            ) from exc

        if count < 1:
            raise RateLimitBackendError(
                "The rate-limit service returned an invalid counter."
            )

        if ttl_milliseconds < 0:
            raise RateLimitBackendError(
                "The rate-limit service returned an invalid expiration."
            )

        return count, ttl_milliseconds

    async def close(self) -> None:
        """Close the rate-limiter adapter.

        The Redis client is shared and owned by ``RedisClient``. It must be
        closed by the application lifespan after all Redis consumers have
        stopped.
        """
        return None


def _validate_hit_arguments(
    *,
    key: str,
    limit: int,
    window_seconds: int,
) -> None:
    """Validate arguments shared by every rate-limit backend.

    Args:
        key: Rate-limit identity key.
        limit: Maximum attempts permitted during the window.
        window_seconds: Window duration in seconds.

    Raises:
        ValueError: If any argument is invalid.
    """
    normalized_key = key.strip()

    if not normalized_key:
        raise ValueError(
            "Rate-limit key must not be blank."
        )

    if limit < 1:
        raise ValueError(
            "Rate-limit limit must be at least 1."
        )

    if window_seconds < 1:
        raise ValueError(
            "Rate-limit window_seconds must be at least 1."
        )


def build_rate_limiter(
    settings: AppSettings,
    *,
    redis_client: object | None = None,
) -> RateLimiter:
    """Build the configured rate-limit backend.

    Args:
        settings: Validated application settings.
        redis_client: Shared asynchronous Redis client. This is required only
            when ``RATE_LIMIT_BACKEND`` is ``redis``.

    Returns:
        Rate limiter matching the configured backend.

    Raises:
        RateLimitBackendError: If Redis is selected but no shared client is
            provided.
        ValueError: If an unsupported backend reaches the factory.
    """
    if settings.RATE_LIMIT_BACKEND is RateLimitBackend.DISABLED:
        return DisabledRateLimiter()

    if settings.RATE_LIMIT_BACKEND is RateLimitBackend.MEMORY:
        return InMemoryRateLimiter()

    if settings.RATE_LIMIT_BACKEND is RateLimitBackend.REDIS:
        if redis_client is None:
            raise RateLimitBackendError(
                "A shared Redis client is required when "
                "RATE_LIMIT_BACKEND=redis."
            )

        return RedisRateLimiter(
            client=redis_client,
            key_prefix=settings.RATE_LIMIT_KEY_PREFIX,
        )

    # This protects the factory if a new enum value is added without a matching
    # implementation.
    raise ValueError(
        "Unsupported rate-limit backend: "
        f"{settings.RATE_LIMIT_BACKEND}"
    )


async def enforce_rate_limit(
    limiter: RateLimiter,
    *,
    keys: list[str],
    limit: int,
    window_seconds: int,
) -> None:
    """Enforce a rate-limit rule against one or more keys.

    Duplicate keys are consumed only once and the original order is preserved.
    Enforcement stops as soon as a key exceeds its configured limit.

    Args:
        limiter: Configured rate-limit backend.
        keys: Identity, IP, device, client, or other rate-limit keys.
        limit: Maximum attempts permitted for each key.
        window_seconds: Fixed-window duration in seconds.

    Raises:
        ValueError: If the key collection or rate-limit arguments are invalid.
        RateLimitError: If any key exceeds the configured limit.
        RateLimitBackendError: If the selected backend fails.
    """
    unique_keys = list(
        dict.fromkeys(
            key.strip()
            for key in keys
            if key and key.strip()
        )
    )

    if not unique_keys:
        raise ValueError(
            "At least one nonblank rate-limit key is required."
        )

    if limit < 1:
        raise ValueError(
            "Rate-limit limit must be at least 1."
        )

    if window_seconds < 1:
        raise ValueError(
            "Rate-limit window_seconds must be at least 1."
        )

    for key in unique_keys:
        decision = await limiter.hit(
            key=key,
            limit=limit,
            window_seconds=window_seconds,
        )

        if not decision.allowed:
            raise RateLimitError(
                retry_after_seconds=decision.retry_after_seconds
            )


__all__ = [
    "DisabledRateLimiter",
    "InMemoryRateLimiter",
    "RateLimitDecision",
    "RateLimiter",
    "RedisRateLimiter",
    "build_rate_limiter",
    "enforce_rate_limit",
]
