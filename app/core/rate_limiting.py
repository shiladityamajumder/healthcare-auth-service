"""Replaceable authentication rate-limiting backends and enforcement helpers."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Protocol

from app.common.exceptions import RateLimitBackendError, RateLimitError
from app.core.config import AppSettings, RateLimitBackend


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter(Protocol):
    async def hit(self, *, key: str, limit: int, window_seconds: int) -> RateLimitDecision: ...

    async def close(self) -> None: ...


class DisabledRateLimiter:
    async def hit(self, *, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        _ = key, window_seconds
        return RateLimitDecision(True, max(limit - 1, 0), 0)

    async def close(self) -> None:
        return None


class InMemoryRateLimiter:
    """Deterministic single-process limiter for local development and tests."""

    def __init__(self) -> None:
        self._entries: dict[str, tuple[int, float]] = {}
        self._lock = asyncio.Lock()

    async def hit(self, *, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        now = time.monotonic()
        async with self._lock:
            count, expires_at = self._entries.get(key, (0, now + window_seconds))
            if expires_at <= now:
                count = 0
                expires_at = now + window_seconds
            count += 1
            self._entries[key] = (count, expires_at)
            retry_after = max(int(expires_at - now), 1)
            return RateLimitDecision(
                allowed=count <= limit,
                remaining=max(limit - count, 0),
                retry_after_seconds=retry_after,
            )

    async def close(self) -> None:
        self._entries.clear()


class RedisRateLimiter:
    _SCRIPT = """
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    local ttl = redis.call('TTL', KEYS[1])
    return {count, ttl}
    """

    def __init__(self, *, url: str, key_prefix: str) -> None:
        try:
            from redis.asyncio import Redis
        except ImportError as exc:
            raise RateLimitBackendError(
                "The Redis package is required for the configured rate limiter."
            ) from exc
        self._client = Redis.from_url(
            url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
            health_check_interval=30,
        )
        self._key_prefix = key_prefix

    async def hit(self, *, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        try:
            raw = await self._client.eval(
                self._SCRIPT,
                1,
                f"{self._key_prefix}:{key}",
                window_seconds,
            )
            count = int(raw[0])
            ttl = max(int(raw[1]), 1)
        except Exception as exc:
            raise RateLimitBackendError() from exc
        return RateLimitDecision(
            allowed=count <= limit,
            remaining=max(limit - count, 0),
            retry_after_seconds=ttl,
        )

    async def close(self) -> None:
        await self._client.aclose()


def build_rate_limiter(settings: AppSettings) -> RateLimiter:
    if settings.RATE_LIMIT_BACKEND is RateLimitBackend.DISABLED:
        return DisabledRateLimiter()
    if settings.RATE_LIMIT_BACKEND is RateLimitBackend.MEMORY:
        return InMemoryRateLimiter()
    return RedisRateLimiter(
        url=settings.redis_url_value,
        key_prefix=settings.RATE_LIMIT_KEY_PREFIX,
    )


async def enforce_rate_limit(
    limiter: RateLimiter,
    *,
    keys: list[str],
    limit: int,
    window_seconds: int,
) -> None:
    for key in dict.fromkeys(keys):
        decision = await limiter.hit(
            key=key,
            limit=limit,
            window_seconds=window_seconds,
        )
        if not decision.allowed:
            raise RateLimitError(retry_after_seconds=decision.retry_after_seconds)


__all__ = [
    "DisabledRateLimiter",
    "InMemoryRateLimiter",
    "RateLimitDecision",
    "RateLimiter",
    "RedisRateLimiter",
    "build_rate_limiter",
    "enforce_rate_limit",
]
