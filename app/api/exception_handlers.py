"""File: app/api/exception_handlers.py

Purpose:
Translates application, framework, and database exceptions into the canonical
external error envelope without exposing unsafe internal details.

Dependency flow:
Route/service/infrastructure exception
-> registered FastAPI exception handler
-> safe status-code and error-code mapping
-> APIResponse.error()
-> request/correlation metadata
-> JSONResponse
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.orm.exc import StaleDataError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.common.exceptions import (
    AppError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    DatabaseError,
    ExternalServiceError,
    InfrastructureError,
    NotFoundError,
    OperationTimeoutError,
    RateLimitError,
    ValidationError,
)
from app.common.response import APIResponse
from app.core.logging import get_logger
from app.core.request_context import get_request_id

logger = get_logger(__name__)

_ERROR_STATUS: tuple[tuple[type[AppError], int], ...] = (
    (AuthenticationError, status.HTTP_401_UNAUTHORIZED),
    (AuthorizationError, status.HTTP_403_FORBIDDEN),
    (NotFoundError, status.HTTP_404_NOT_FOUND),
    (ConflictError, status.HTTP_409_CONFLICT),
    (RateLimitError, status.HTTP_429_TOO_MANY_REQUESTS),
    (ValidationError, status.HTTP_422_UNPROCESSABLE_CONTENT),
    (OperationTimeoutError, status.HTTP_504_GATEWAY_TIMEOUT),
    (ExternalServiceError, status.HTTP_503_SERVICE_UNAVAILABLE),
    (DatabaseError, status.HTTP_503_SERVICE_UNAVAILABLE),
    (InfrastructureError, status.HTTP_503_SERVICE_UNAVAILABLE),
)


def _status_for(error: AppError) -> int:
    for error_type, status_code in _ERROR_STATUS:
        if isinstance(error, error_type):
            return status_code
    return status.HTTP_400_BAD_REQUEST


async def app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    error = cast(AppError, exc)
    status_code = _status_for(error)
    headers: dict[str, str] = {}
    if isinstance(error, RateLimitError):
        headers["Retry-After"] = str(error.retry_after_seconds)
    if isinstance(error, AuthenticationError):
        headers["WWW-Authenticate"] = "Bearer"

    logger.warning(
        "Expected application error",
        extra={
            "error_code": error.code,
            "status_code": status_code,
            "method": request.method,
            "route": getattr(request.scope.get("route"), "path", "unmatched"),
        },
    )
    return APIResponse.error(
        error_code=error.code,
        message=error.message,
        status_code=status_code,
        details=error.details,
        headers=headers or None,
    )


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    validation_error = cast(RequestValidationError, exc)
    details: list[dict[str, str]] = []
    for item in validation_error.errors():
        details.append(
            {
                "field": ".".join(str(part) for part in item.get("loc", ())),
                "message": str(item.get("msg", "Invalid value")),
                "type": str(item.get("type", "validation_error")),
            }
        )
    logger.info(
        "Request validation failed",
        extra={
            "error_count": len(details),
            "method": request.method,
            "route": getattr(request.scope.get("route"), "path", "unmatched"),
        },
    )
    return APIResponse.error(
        error_code="REQUEST_VALIDATION_ERROR",
        message="The request contains invalid input.",
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        details=details,
    )


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    _ = request
    http_error = cast(StarletteHTTPException, exc)
    code_by_status = {
        400: "BAD_REQUEST",
        401: "AUTHENTICATION_REQUIRED",
        403: "PERMISSION_DENIED",
        404: "ROUTE_NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        413: "PAYLOAD_TOO_LARGE",
        415: "UNSUPPORTED_MEDIA_TYPE",
    }
    error_code = code_by_status.get(http_error.status_code, "HTTP_ERROR")
    detail: object = http_error.detail
    if http_error.status_code >= 500:
        message = "An unexpected server error occurred."
    elif isinstance(detail, str):
        message = detail
    else:
        message = "The request could not be processed."
    return APIResponse.error(
        error_code=error_code,
        message=message,
        status_code=http_error.status_code,
        headers=dict(http_error.headers or {}),
    )


async def sqlalchemy_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Map database failures without returning SQL or driver details."""
    if isinstance(exc, StaleDataError):
        status_code = status.HTTP_409_CONFLICT
        error_code = "CONCURRENT_UPDATE_CONFLICT"
        message = "The record changed during this operation. Reload and retry."
    elif isinstance(exc, IntegrityError):
        status_code = status.HTTP_409_CONFLICT
        error_code = "RESOURCE_CONFLICT"
        message = "The operation conflicts with existing data."
    elif isinstance(exc, OperationalError):
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        error_code = "DATABASE_UNAVAILABLE"
        message = "The persistence service is temporarily unavailable."
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        error_code = "DATABASE_ERROR"
        message = "A persistence operation failed."

    logger.error(
        "SQLAlchemy operation failed",
        extra={
            "request_id": get_request_id(),
            "method": request.method,
            "route": getattr(request.scope.get("route"), "path", "unmatched"),
            "exception_type": type(exc).__name__,
        },
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return APIResponse.error(
        error_code=error_code,
        message=message,
        status_code=status_code,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Log the internal failure and return a deliberately generic response."""
    logger.error(
        "Unhandled application exception",
        extra={
            "request_id": get_request_id(),
            "method": request.method,
            "route": getattr(request.scope.get("route"), "path", "unmatched"),
            "exception_type": type(exc).__name__,
        },
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return APIResponse.error(
        error_code="INTERNAL_SERVER_ERROR",
        message="An unexpected server error occurred.",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


def register_exception_handlers(app: FastAPI) -> None:
    handlers: tuple[tuple[type[Exception], Callable[..., Any]], ...] = (
        (AppError, app_error_handler),
        (RequestValidationError, validation_exception_handler),
        (StarletteHTTPException, http_exception_handler),
        (StaleDataError, sqlalchemy_exception_handler),
        (SQLAlchemyError, sqlalchemy_exception_handler),
        (Exception, unhandled_exception_handler),
    )
    for exception_type, handler in handlers:
        app.add_exception_handler(exception_type, handler)


__all__ = ["register_exception_handlers"]
