"""File: app/main.py

Purpose:
Builds the FastAPI application and registers lifecycle, middleware, routers,
exception handlers, and the root response.

Dependency flow:
Process startup
-> create_app()
-> lifespan-managed infrastructure on app.state
-> middleware and versioned/health routers
-> centralized exception handlers
-> FastAPI application
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.api.exception_handlers import register_exception_handlers
from app.api.health import router as health_router
from app.api.v1.router import router as api_v1_router
from app.common.response import APIResponse
from app.core.config import AppSettings, get_settings
from app.core.lifespan import lifespan
from app.core.logging import setup_logging
from app.core.middleware import register_middleware


def create_app(settings: AppSettings | None = None) -> FastAPI:
    """Build an isolated application instance.

    Tests can supply a validated settings instance. Runtime code loads the
    cached environment-backed instance exactly once.
    """

    resolved = settings or get_settings()
    setup_logging(resolved)

    app = FastAPI(
        title=resolved.PROJECT_NAME,
        version=resolved.APP_VERSION,
        debug=resolved.DEBUG,
        docs_url="/docs" if resolved.DOCS_ENABLED else None,
        redoc_url="/redoc" if resolved.DOCS_ENABLED else None,
        openapi_url="/openapi.json" if resolved.DOCS_ENABLED else None,
        lifespan=lifespan,
        swagger_ui_parameters={
            "persistAuthorization": False,
            "displayRequestDuration": True,
            "filter": True,
        },
    )

    app.state.settings = resolved
    app.state.ready = False
    app.state.database = None
    app.state.auth_runtime = None

    register_middleware(app, resolved)
    register_exception_handlers(app)

    app.include_router(health_router)
    app.include_router(api_v1_router, prefix=resolved.API_V1_STR)

    @app.get("/", tags=["System"], summary="Service descriptor")
    async def root() -> JSONResponse:
        """Return the public service descriptor and configured discovery links."""
        return APIResponse.success(
            data={
                "service": resolved.PROJECT_NAME,
                "version": resolved.APP_VERSION,
                "api_base": resolved.API_V1_STR,
                "documentation": "/docs" if resolved.DOCS_ENABLED else None,
                "health": {
                    "liveness": "/health/live",
                    "readiness": "/health/ready",
                    "deep": "/health/deep" if resolved.DEEP_HEALTH_ENABLED else None,
                },
            }
        )

    return app


app = create_app()


__all__ = ["app", "create_app"]
