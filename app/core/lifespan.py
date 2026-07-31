"""File: app/core/lifespan.py

Purpose:
Creates, publishes, health-checks, and closes process-wide infrastructure for
the FastAPI application lifecycle.

Dependency flow:
Validated AppSettings
-> PostgreSQL and optional Redis/Mongo clients
-> rate limiter and AuthRuntime
-> references stored on app.state
-> request dependencies
-> reverse-order shutdown

This module owns the process-wide lifecycle of infrastructure dependencies:

* PostgreSQL
* Optional Redis
* Optional MongoDB
* Authentication runtime

Infrastructure clients are created once per application process and shared
through ``app.state``. Request handlers and repositories must not create their
own database or Redis clients.

PostgreSQL may start in degraded mode when explicitly configured. Redis and
MongoDB are treated as required whenever they are enabled because no separate
fail-fast policy currently exists for those integrations.
"""

from __future__ import annotations

import asyncio
from collections.abc import (
    AsyncGenerator,
    Awaitable,
    Callable,
)
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI

from app.auth.infrastructure.runtime import AuthRuntime
from app.core.config import AppSettings
from app.core.logging import get_logger
from app.core.rate_limiting import (
    RateLimiter,
    build_rate_limiter,
)
from app.db.postgres import PostgreSQLDatabase

if TYPE_CHECKING:
    from app.db.mongo import MongoDatabase
    from app.db.redis_client import RedisClient


logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(
    app: FastAPI,
) -> AsyncGenerator[None, None]:
    """Initialize and close process-wide application infrastructure.

    PostgreSQL connectivity is not required for the ASGI process to start
    unless ``DATABASE_FAIL_FAST`` is enabled.

    When PostgreSQL is unavailable and fail-fast is disabled, the service
    starts in degraded mode. Liveness and documentation may remain available,
    while readiness and PostgreSQL-backed endpoints should report service
    unavailability.

    Redis is initialized when either:

    * ``ENABLE_REDIS`` is true, or
    * ``RATE_LIMIT_BACKEND`` is ``redis``.

    MongoDB is initialized only when ``ENABLE_MONGO`` is true.

    Args:
        app: FastAPI application instance.

    Yields:
        Control to FastAPI while the application is running.

    Raises:
        RuntimeError: If required infrastructure cannot be initialized.
        Exception: Propagates unexpected startup failures after attempting
            resource cleanup.
    """
    settings: AppSettings = app.state.settings

    database = PostgreSQLDatabase(settings)

    redis_adapter: RedisClient | None = None
    mongo_database: MongoDatabase | None = None
    rate_limiter: RateLimiter | None = None
    auth_runtime: AuthRuntime | None = None

    _initialize_application_state(
        app=app,
        database=database,
    )

    logger.info(
        "Application startup initiated",
        extra={
            "environment": settings.ENVIRONMENT.value,
            "database_startup_check": (settings.DATABASE_STARTUP_CHECK),
            "database_fail_fast": settings.DATABASE_FAIL_FAST,
            "redis_enabled": settings.redis_enabled,
            "mongo_enabled": settings.ENABLE_MONGO,
            "rate_limit_backend": (settings.RATE_LIMIT_BACKEND.value),
        },
    )

    try:
        startup_mode = await _initialize_postgresql(
            app=app,
            database=database,
            settings=settings,
        )

        if settings.redis_enabled:
            redis_adapter = await _initialize_redis(
                app=app,
                settings=settings,
            )

        if settings.ENABLE_MONGO:
            mongo_database = await _initialize_mongodb(
                app=app,
                settings=settings,
            )

        rate_limiter = build_rate_limiter(
            settings,
            redis_client=(redis_adapter.client if redis_adapter is not None else None),
        )

        # AuthRuntime must consume the already-created rate limiter. It must
        # not create a second Redis client or an independent rate limiter.
        auth_runtime = AuthRuntime.from_settings(
            settings,
            rate_limiter=rate_limiter,
        )

        app.state.auth_runtime = auth_runtime
        app.state.startup_mode = startup_mode

        # This flag indicates that FastAPI startup completed successfully.
        # Dependency readiness must still be evaluated by the readiness
        # endpoint using the stored infrastructure health state.
        app.state.ready = True

        logger.info(
            "Application startup complete",
            extra={
                "startup_mode": startup_mode,
                "postgresql_configured": True,
                "redis_initialized": redis_adapter is not None,
                "mongo_initialized": mongo_database is not None,
                "rate_limit_backend": (settings.RATE_LIMIT_BACKEND.value),
            },
        )

        yield

    except Exception:
        logger.exception(
            "Application startup or runtime failure",
            extra={
                "startup_mode": app.state.startup_mode,
            },
        )
        raise

    finally:
        app.state.ready = False
        app.state.startup_mode = "stopping"

        logger.info("Application shutdown initiated")

        # Remove externally accessible references before closing resources.
        # This prevents new application code from retrieving dependencies
        # while shutdown is already in progress.
        app.state.auth_runtime = None
        app.state.mongo_database = None
        app.state.redis_client = None

        if rate_limiter is not None:
            await _close_safely(
                resource_name="rate limiter",
                close=rate_limiter.close,
            )

        if mongo_database is not None:
            await _close_safely(
                resource_name="MongoDB client",
                close=mongo_database.close,
            )

        if redis_adapter is not None:
            await _close_safely(
                resource_name="Redis client",
                close=redis_adapter.close,
            )

        await _close_safely(
            resource_name="PostgreSQL database",
            close=database.close,
        )

        app.state.database = None
        app.state.database_health = None
        app.state.redis_health = None
        app.state.mongo_health = None
        app.state.startup_mode = "stopped"

        logger.info("Application shutdown complete")


def _initialize_application_state(
    *,
    app: FastAPI,
    database: PostgreSQLDatabase,
) -> None:
    """Initialize application-state fields before startup work begins.

    Initializing all fields up front keeps health checks and exception handling
    predictable even when startup fails partway through.

    Args:
        app: FastAPI application instance.
        database: Process-wide PostgreSQL adapter.
    """
    app.state.ready = False
    app.state.startup_mode = "starting"

    app.state.database = database
    app.state.database_health = None

    app.state.redis_client = None
    app.state.redis_health = None

    app.state.mongo_database = None
    app.state.mongo_health = None

    app.state.auth_runtime = None


async def _initialize_postgresql(
    *,
    app: FastAPI,
    database: PostgreSQLDatabase,
    settings: AppSettings,
) -> str:
    """Initialize and optionally validate PostgreSQL.

    Args:
        app: FastAPI application instance.
        database: PostgreSQL lifecycle adapter.
        settings: Validated application settings.

    Returns:
        Startup mode: ``normal``, ``degraded``, or ``unchecked``.

    Raises:
        RuntimeError: If PostgreSQL validation fails while fail-fast behavior
            is enabled.
    """
    if not settings.DATABASE_STARTUP_CHECK:
        logger.warning(
            "PostgreSQL startup validation is disabled",
        )

        return "unchecked"

    health = await database.check(
        timeout_seconds=settings.HEALTHCHECK_TIMEOUT_SECONDS,
        verify_schema=settings.DATABASE_SCHEMA_CHECK,
    )

    app.state.database_health = health

    database_ready = health.healthy and health.schema_ready

    if database_ready:
        logger.info(
            "PostgreSQL startup validation succeeded",
            extra={
                "postgresql_healthy": health.healthy,
                "identity_schema_ready": health.schema_ready,
                "duration_ms": health.duration_ms,
            },
        )

        return "normal"

    logger.warning(
        "PostgreSQL validation failed; degraded startup requested",
        extra={
            "postgresql_healthy": health.healthy,
            "identity_schema_ready": health.schema_ready,
            "duration_ms": health.duration_ms,
            "database_fail_fast": settings.DATABASE_FAIL_FAST,
        },
    )

    if settings.DATABASE_FAIL_FAST:
        raise RuntimeError("PostgreSQL connectivity or identity schema validation failed")

    return "degraded"


async def _initialize_redis(
    *,
    app: FastAPI,
    settings: AppSettings,
) -> RedisClient:
    """Create and validate the process-wide Redis client.

    Redis is imported lazily so development and testing environments that do
    not enable Redis are not forced to import the optional driver.

    Args:
        app: FastAPI application instance.
        settings: Validated application settings.

    Returns:
        Connected process-wide Redis adapter.

    Raises:
        RuntimeError: If redis-py is unavailable or Redis validation fails.
    """
    try:
        from app.db.redis_client import RedisClient
    except ImportError as exc:
        app.state.redis_health = False

        raise RuntimeError("Redis is enabled but the redis package is unavailable") from exc

    redis_adapter = RedisClient.from_settings(settings)

    try:
        await asyncio.wait_for(
            redis_adapter.ping(),
            timeout=settings.HEALTHCHECK_TIMEOUT_SECONDS,
        )
    except Exception:
        app.state.redis_health = False

        await _close_safely(
            resource_name="partially initialized Redis client",
            close=redis_adapter.close,
        )

        raise

    app.state.redis_client = redis_adapter
    app.state.redis_health = True

    logger.info(
        "Redis startup validation succeeded",
        extra={
            "max_connections": settings.REDIS_MAX_CONNECTIONS,
            "rate_limit_backend": (settings.RATE_LIMIT_BACKEND.value),
        },
    )

    return redis_adapter


async def _initialize_mongodb(
    *,
    app: FastAPI,
    settings: AppSettings,
) -> MongoDatabase:
    """Create and validate the process-wide MongoDB client.

    MongoDB is imported lazily because it is an optional infrastructure
    integration.

    Args:
        app: FastAPI application instance.
        settings: Validated application settings.

    Returns:
        Connected process-wide MongoDB adapter.

    Raises:
        RuntimeError: If PyMongo is unavailable or MongoDB validation fails.
    """
    try:
        from app.db.mongo import MongoDatabase
    except ImportError as exc:
        app.state.mongo_health = False

        raise RuntimeError("MongoDB is enabled but the pymongo package is unavailable") from exc

    mongo_database = MongoDatabase.from_settings(settings)

    try:
        await asyncio.wait_for(
            mongo_database.ping(),
            timeout=settings.HEALTHCHECK_TIMEOUT_SECONDS,
        )
    except Exception:
        app.state.mongo_health = False

        await _close_safely(
            resource_name="partially initialized MongoDB client",
            close=mongo_database.close,
        )

        raise

    app.state.mongo_database = mongo_database
    app.state.mongo_health = True

    logger.info(
        "MongoDB startup validation succeeded",
        extra={
            "database": settings.MONGO_DB_NAME,
            "min_pool_size": settings.MONGO_MIN_POOL_SIZE,
            "max_pool_size": settings.MONGO_MAX_POOL_SIZE,
        },
    )

    return mongo_database


async def _close_safely(
    *,
    resource_name: str,
    close: Callable[[], Awaitable[None]],
) -> None:
    """Close one resource without preventing later cleanup.

    Shutdown should attempt to close every initialized resource even when one
    close operation fails.

    Args:
        resource_name: Human-readable resource name used in logs.
        close: Asynchronous close callback.
    """
    try:
        await close()
    except Exception:
        logger.exception(
            "Infrastructure resource failed to close",
            extra={
                "resource": resource_name,
            },
        )


__all__ = ["lifespan"]
