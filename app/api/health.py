"""File: app/api/health.py

Purpose:
Defines the ``/health`` liveness, readiness, and bounded PostgreSQL diagnostic
endpoints.

Dependency flow:
HTTP health request
-> FastAPI route
-> app.state settings/PostgreSQL infrastructure
-> bounded readiness or deep-health probe
-> APIResponse
"""

from __future__ import annotations

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.common.response import APIResponse
from app.core.config import AppSettings
from app.db.postgres import PostgreSQLDatabase

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/live", summary="Process liveness")
async def liveness() -> JSONResponse:
    """Return public process liveness without probing external dependencies."""
    return APIResponse.success(data={"status": "alive"})


@router.get("/ready", summary="Traffic readiness")
async def readiness(request: Request) -> JSONResponse:
    """Return public readiness after a bounded PostgreSQL/schema check.

    The route reads lifespan-owned infrastructure from ``app.state``; request
    context is not authentication or authorization.
    """
    if not getattr(request.app.state, "ready", False):
        return APIResponse.error(
            error_code="SERVICE_NOT_READY",
            message="The service is not ready to receive traffic.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    settings: AppSettings = request.app.state.settings
    database: PostgreSQLDatabase = request.app.state.database
    check = await database.check(
        timeout_seconds=settings.HEALTHCHECK_TIMEOUT_SECONDS,
        verify_schema=settings.DATABASE_SCHEMA_CHECK,
    )

    if not check.healthy or not check.schema_ready:
        return APIResponse.error(
            error_code="SERVICE_NOT_READY",
            message="PostgreSQL or a required migrated schema is unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details={
                "checks": {
                    "postgresql": {
                        "healthy": check.healthy,
                        "schema_ready": check.schema_ready,
                    }
                }
            },
        )

    return APIResponse.success(
        data={
            "ready": True,
            "checks": {
                "postgresql": {
                    "healthy": True,
                    "schema_ready": check.schema_ready,
                }
            },
        }
    )


@router.get("/deep", summary="Detailed bounded dependency diagnostics")
async def deep_health(request: Request) -> JSONResponse:
    """Return detailed bounded database diagnostics when explicitly enabled.

    This public diagnostic is hidden with a not-found response when deep health
    is disabled by configuration.
    """
    settings: AppSettings = request.app.state.settings
    if not settings.DEEP_HEALTH_ENABLED:
        return APIResponse.error(
            error_code="ROUTE_NOT_FOUND",
            message="The requested route was not found.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    database: PostgreSQLDatabase = request.app.state.database
    check = await database.check(
        timeout_seconds=settings.HEALTHCHECK_TIMEOUT_SECONDS,
        verify_schema=settings.DATABASE_SCHEMA_CHECK,
    )
    payload = {
        "healthy": check.healthy and check.schema_ready,
        "checks": {
            "postgresql": {
                "healthy": check.healthy,
                "schema_ready": check.schema_ready,
                "duration_ms": check.duration_ms,
            }
        },
    }

    if not check.healthy or not check.schema_ready:
        return APIResponse.error(
            error_code="DEPENDENCY_HEALTH_CHECK_FAILED",
            message="PostgreSQL failed the health check.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=payload,
        )

    return APIResponse.success(data=payload)


__all__ = ["router"]
