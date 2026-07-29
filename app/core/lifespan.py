"""FastAPI startup and shutdown orchestration."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import AppSettings
from app.core.logging import get_logger
from app.db.postgres import PostgreSQLDatabase
from app.auth.runtime import AuthRuntime

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Initialize process-wide infrastructure.

    PostgreSQL connectivity is not required for the ASGI process to start
    unless DATABASE_FAIL_FAST is explicitly enabled.

    When PostgreSQL is unavailable, the service starts in degraded mode:
    liveness and documentation remain accessible, while readiness and
    database-backed endpoints report service unavailability.
    """

    settings: AppSettings = app.state.settings
    database = PostgreSQLDatabase(settings)

    app.state.ready = False
    app.state.database = database
    app.state.database_health = None
    app.state.auth_runtime = AuthRuntime.from_settings(settings)

    logger.info(
        "Application startup initiated",
        extra={
            "database_startup_check": settings.DATABASE_STARTUP_CHECK,
            "database_fail_fast": settings.DATABASE_FAIL_FAST,
        },
    )

    try:
        if settings.DATABASE_STARTUP_CHECK:
            health = await database.check(
                timeout_seconds=settings.HEALTHCHECK_TIMEOUT_SECONDS,
                verify_schema=settings.DATABASE_SCHEMA_CHECK,
            )

            app.state.database_health = health

            database_ready = health.healthy and health.schema_ready

            if not database_ready:
                logger.warning(
                    "Application starting in degraded mode",
                    extra={
                        "postgresql_healthy": health.healthy,
                        "identity_schema_ready": health.schema_ready,
                        "duration_ms": health.duration_ms,
                    },
                )

                if settings.DATABASE_FAIL_FAST:
                    raise RuntimeError(
                        "PostgreSQL connectivity or identity schema "
                        "validation failed"
                    )

        # This indicates that FastAPI startup completed.
        # Dependency readiness is checked separately by /health/ready.
        app.state.ready = True

        logger.info(
            "Application startup complete",
            extra={
                "database": "postgresql",
                "startup_mode": (
                    "normal"
                    if (
                        app.state.database_health is not None
                        and app.state.database_health.healthy
                        and app.state.database_health.schema_ready
                    )
                    else "degraded"
                ),
            },
        )

        yield

    except Exception:
        logger.exception("Application startup or runtime failure")
        raise

    finally:
        app.state.ready = False
        runtime = app.state.auth_runtime
        if runtime is not None:
            await runtime.rate_limiter.close()
        app.state.auth_runtime = None
        app.state.database_health = None

        logger.info("Application shutdown initiated")

        await database.close()

        app.state.database = None

        logger.info("Application shutdown complete")


__all__ = ["lifespan"]