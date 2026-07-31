"""File: app/db/redis_client.py

Purpose:
Owns the process-wide Redis connection pool, shared client, and bounded
connectivity checks used by Redis-backed infrastructure.

Dependency flow:
Validated Redis settings
-> lifespan creates RedisClient
-> connect()/health_check()
-> shared rate-limit backend client
-> close() during shutdown

This module owns one process-wide asynchronous Redis client and its connection
pool. The client is created during FastAPI startup, shared by Redis-dependent
infrastructure, and closed during application shutdown.

Consumers such as rate limiting, caching, and idempotency must reuse this
client instead of creating independent Redis connection pools.
"""

from __future__ import annotations

import asyncio
from typing import Protocol, Self, cast

from redis.asyncio import BlockingConnectionPool, Redis

from app.core.config import AppSettings
from app.core.logging import get_logger

logger = get_logger(__name__)


class _AsyncRedisLifecycle(Protocol):
    """Minimal asynchronous Redis lifecycle operations.

    Some redis-py and editor type-stub combinations incorrectly resolve
    asynchronous Redis commands as synchronous return values. This protocol
    explicitly defines the awaitable operations used by this adapter.
    """

    async def ping(self) -> bool:
        """Execute the Redis PING command asynchronously."""

        ...

    async def aclose(
        self,
        close_connection_pool: bool | None = None,
    ) -> None:
        """Close client-owned resources asynchronously."""

        ...


class _AsyncRedisPoolLifecycle(Protocol):
    """Minimal asynchronous Redis connection-pool lifecycle contract."""

    async def disconnect(
        self,
        inuse_connections: bool = True,
    ) -> None:
        """Disconnect connections managed by the pool."""

        ...


class RedisClient:
    """Own one process-wide Redis client and connection pool.

    One adapter instance should be created during application startup and
    shared across requests.

    The adapter owns both the Redis client and the connection pool. Other
    infrastructure components may use ``client`` but must not close it.
    """

    def __init__(
        self,
        *,
        url: str,
        settings: AppSettings,
    ) -> None:
        """Initialize the shared asynchronous Redis client.

        Args:
            url: Validated Redis connection URL.
            settings: Validated application configuration.

        Raises:
            ValueError: If the Redis URL is blank.
        """
        normalized_url = url.strip()

        if not normalized_url:
            raise ValueError("Redis connection URL must not be blank.")

        pool = BlockingConnectionPool.from_url(
            normalized_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            timeout=settings.REDIS_POOL_TIMEOUT_SECONDS,
            socket_timeout=(settings.REDIS_SOCKET_TIMEOUT_SECONDS),
            socket_connect_timeout=(settings.REDIS_CONNECT_TIMEOUT_SECONDS),
            health_check_interval=(settings.REDIS_HEALTH_CHECK_INTERVAL_SECONDS),
            client_name=settings.PROJECT_NAME,
        )

        client = Redis(
            connection_pool=pool,
        )

        self._client: Redis = client
        self._pool: BlockingConnectionPool = pool

        # These narrow protocol views fix incorrect synchronous type inference
        # without weakening type checking for the rest of the Redis client.
        self._async_client = cast(
            _AsyncRedisLifecycle,
            client,
        )
        self._async_pool = cast(
            _AsyncRedisPoolLifecycle,
            pool,
        )

        self._close_lock = asyncio.Lock()
        self._closed = False

        logger.info(
            "Redis client initialized",
            extra={
                "max_connections": settings.REDIS_MAX_CONNECTIONS,
                "pool_timeout_seconds": (settings.REDIS_POOL_TIMEOUT_SECONDS),
                "socket_timeout_seconds": (settings.REDIS_SOCKET_TIMEOUT_SECONDS),
                "connect_timeout_seconds": (settings.REDIS_CONNECT_TIMEOUT_SECONDS),
            },
        )

    @classmethod
    def from_settings(
        cls,
        settings: AppSettings,
    ) -> Self:
        """Build the Redis adapter from validated settings.

        Redis is considered enabled when it is explicitly enabled or when the
        configured rate-limit backend requires Redis.

        Args:
            settings: Validated application configuration.

        Returns:
            Initialized Redis lifecycle adapter.

        Raises:
            RuntimeError: If Redis is not enabled.
            ValueError: If Redis is enabled but its URL is unavailable.
        """
        if not settings.redis_enabled:
            raise RuntimeError("Redis is not enabled.")

        return cls(
            url=settings.redis_url_value,
            settings=settings,
        )

    @property
    def client(self) -> Redis:
        """Return the shared asynchronous Redis client.

        The returned client is owned by this adapter. Consumers must not call
        ``aclose`` or disconnect its connection pool.

        Returns:
            Process-wide asynchronous Redis client.

        Raises:
            RuntimeError: If the adapter has already been closed.
        """
        self._ensure_open()

        return self._client

    @property
    def closed(self) -> bool:
        """Return whether the Redis adapter has been closed."""
        return self._closed

    async def ping(self) -> None:
        """Verify Redis connectivity and command execution.

        Raises:
            RuntimeError: If the adapter is closed or Redis returns an
                unexpected PING result.
            Exception: Propagates Redis connection, authentication, and timeout
                failures to the application lifecycle boundary.
        """
        self._ensure_open()

        result = await self._async_client.ping()

        if result is not True:
            raise RuntimeError("Redis returned an unexpected PING response.")

        logger.debug(
            "Redis connectivity verified",
        )

    async def close(self) -> None:
        """Close the Redis client and its connection pool.

        The method is idempotent. Multiple shutdown paths may safely call it,
        but only the first call performs resource cleanup.

        Raises:
            Exception: Propagates failures encountered while disconnecting the
                client or connection pool.
        """
        async with self._close_lock:
            if self._closed:
                return

            try:
                await self._async_client.aclose()
            finally:
                # The pool was created separately and passed into Redis, so
                # this adapter explicitly disconnects all pooled connections.
                await self._async_pool.disconnect(
                    inuse_connections=True,
                )

            self._closed = True

            logger.info(
                "Redis client closed",
            )

    def _ensure_open(self) -> None:
        """Reject operations after the adapter has been closed.

        Raises:
            RuntimeError: If shutdown has already closed the Redis client.
        """
        if self._closed:
            raise RuntimeError("Redis client is closed.")


__all__ = [
    "RedisClient",
]
