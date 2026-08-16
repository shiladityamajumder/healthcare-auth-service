"""File: app/core/middleware.py

Purpose:
Registers pure-ASGI request context, security-header, body-limit, CORS, and
observability middleware.

Dependency flow:
ASGI request scope/messages
-> ordered middleware stack
-> request/correlation context and transport guards
-> FastAPI route
-> response headers and access log
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from urllib.parse import urlsplit

from fastapi import FastAPI
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.common.response import APIResponse
from app.core.config import AppSettings
from app.core.logging import get_logger
from app.core.request_context import (
    reset_request_context,
    set_request_context,
)

logger = get_logger(__name__)

_TRACEPARENT_PATTERN = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")


def _validated_uuid_header(value: str | None) -> str | None:
    """Validate an optional UUID header without accepting arbitrary identifiers."""
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        raise ValueError("identifier header must not be blank")
    if len(normalized) > 36:
        raise ValueError("identifier header is too long")
    return str(uuid.UUID(normalized))


def _extract_trace_id(
    traceparent: str | None,
) -> str | None:
    """Extract a valid trace identifier from a W3C traceparent header.

    Args:
        traceparent: Raw traceparent header.

    Returns:
        Trace identifier or ``None``.
    """
    if not traceparent:
        return None

    match = _TRACEPARENT_PATTERN.fullmatch(
        traceparent.strip().lower(),
    )

    if match and match.group(1) != "0" * 32:
        return match.group(1)

    return None


def _hash_client_ip(
    scope: Scope,
) -> str | None:
    """Hash the client IP for privacy-safe request logging.

    Args:
        scope: Current ASGI scope.

    Returns:
        Stable hashed client IP or ``None``.
    """
    client = scope.get("client")

    if not client:
        return None

    return hashlib.blake2b(
        str(client[0]).encode("utf-8"),
        digest_size=12,
    ).hexdigest()


class RequestContextMiddleware:
    """Bind validated request, correlation, and trace identifiers."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        api_version: str,
    ) -> None:
        self.app = app
        self.api_version = api_version.strip("/") or "v1"

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Process one ASGI request."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)

        request_id = str(uuid.uuid4())
        correlation_id = request_id
        invalid_header: tuple[str, str] | None = None
        try:
            request_id = _validated_uuid_header(headers.get("x-request-id")) or request_id
        except ValueError:
            invalid_header = ("INVALID_REQUEST_ID", "X-Request-ID must be a valid UUID.")

        if invalid_header is None:
            try:
                correlation_id = (
                    _validated_uuid_header(headers.get("x-correlation-id")) or request_id
                )
            except ValueError:
                invalid_header = (
                    "INVALID_CORRELATION_ID",
                    "X-Correlation-ID must be a valid UUID.",
                )
                correlation_id = request_id

        trace_id = _extract_trace_id(headers.get("traceparent"))

        tokens = set_request_context(
            request_id=request_id,
            correlation_id=correlation_id,
            trace_id=trace_id,
            api_version=self.api_version,
        )

        if invalid_header is not None:
            error_code, message = invalid_header
            try:
                response = APIResponse.error(
                    error_code=error_code,
                    message=message,
                    status_code=400,
                )
                response.headers["X-API-Version"] = self.api_version
                await response(scope, receive, send)
            finally:
                reset_request_context(tokens)
            return

        async def send_wrapper(
            message: Message,
        ) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(
                    scope=message,
                )

                response_headers["X-Request-ID"] = request_id
                response_headers["X-Correlation-ID"] = correlation_id
                response_headers["X-API-Version"] = self.api_version

            await send(message)

        try:
            await self.app(
                scope,
                receive,
                send_wrapper,
            )
        finally:
            reset_request_context(tokens)


class RequestLoggingMiddleware:
    """Emit one bounded-cardinality completion log per HTTP request."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        slow_threshold_ms: int,
    ) -> None:
        self.app = app
        self.slow_threshold_ms = slow_threshold_ms

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Process and log one ASGI request."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500
        escaped_exception = False

        async def send_wrapper(
            message: Message,
        ) -> None:
            nonlocal status_code

            if message["type"] == "http.response.start":
                status_code = int(message["status"])

            await send(message)

        try:
            await self.app(
                scope,
                receive,
                send_wrapper,
            )
        except Exception:
            escaped_exception = True
            raise
        finally:
            duration_ms = round(
                (time.perf_counter() - started) * 1_000,
                2,
            )

            route = getattr(
                scope.get("route"),
                "path",
                "unmatched",
            )

            log_method = logger.warning if duration_ms >= self.slow_threshold_ms else logger.info

            log_method(
                "HTTP request completed",
                extra={
                    "method": scope.get("method"),
                    "route": route,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "client_ip_hash": _hash_client_ip(scope),
                    "exception_escaped": escaped_exception,
                },
            )


class RequestSizeLimitMiddleware:
    """Reject oversized fixed-length and chunked request bodies."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int,
    ) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Process one ASGI request while enforcing body limits."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = Headers(
            scope=scope,
        ).get("content-length")

        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                response = APIResponse.error(
                    error_code="INVALID_CONTENT_LENGTH",
                    message="The Content-Length header is invalid.",
                    status_code=400,
                )

                await response(
                    scope,
                    receive,
                    send,
                )
                return

            if declared_length < 0:
                response = APIResponse.error(
                    error_code="INVALID_CONTENT_LENGTH",
                    message="The Content-Length header is invalid.",
                    status_code=400,
                )

                await response(
                    scope,
                    receive,
                    send,
                )
                return

            if declared_length > self.max_body_bytes:
                await self._send_too_large(
                    scope,
                    receive,
                    send,
                )
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received

            message = await receive()

            if message["type"] == "http.request":
                received += len(
                    message.get("body", b""),
                )

                if received > self.max_body_bytes:
                    raise _RequestBodyTooLarge

            return message

        try:
            await self.app(
                scope,
                limited_receive,
                send,
            )
        except _RequestBodyTooLarge:
            await self._send_too_large(
                scope,
                receive,
                send,
            )

    async def _send_too_large(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Send a standardized payload-too-large response."""
        response = APIResponse.error(
            error_code="PAYLOAD_TOO_LARGE",
            message="The request body exceeds the allowed size.",
            status_code=413,
            details={
                "max_bytes": self.max_body_bytes,
            },
        )

        await response(
            scope,
            receive,
            send,
        )


class _RequestBodyTooLarge(Exception):
    """Internal control-flow exception for chunked request overflow."""


class SecurityHeadersMiddleware:
    """Add conservative API security and cache-control headers."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        enabled: bool,
        hsts_enabled: bool,
    ) -> None:
        self.app = app
        self.enabled = enabled
        self.hsts_enabled = hsts_enabled

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Process one ASGI request and attach security headers."""
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        async def send_wrapper(
            message: Message,
        ) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(
                    scope=message,
                )

                headers.setdefault(
                    "Cache-Control",
                    "no-store",
                )
                headers.setdefault(
                    "X-Content-Type-Options",
                    "nosniff",
                )
                headers.setdefault(
                    "X-Frame-Options",
                    "DENY",
                )
                headers.setdefault(
                    "Referrer-Policy",
                    "no-referrer",
                )
                headers.setdefault(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=()",
                )

                if self.hsts_enabled:
                    headers.setdefault(
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    )

            await send(message)

        await self.app(
            scope,
            receive,
            send_wrapper,
        )


class TrustedHostValidationMiddleware:
    """Reject untrusted Host headers using an explicit allow-list."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        enabled: bool,
        allowed_hosts: list[str],
    ) -> None:
        self.app = app
        self.enabled = enabled

        self.allowed_hosts = tuple(
            host.strip().casefold().rstrip(".") for host in allowed_hosts if host and host.strip()
        )

    def _is_allowed(
        self,
        host: str,
    ) -> bool:
        """Return whether a normalized hostname is allowed."""
        if not self.enabled:
            return True

        normalized = host.casefold().rstrip(".")

        for allowed in self.allowed_hosts:
            if allowed == normalized:
                return True

            if allowed.startswith("*.") and normalized.endswith(allowed[1:]):
                return True

        return False

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Validate the HTTP Host header when enforcement is enabled."""
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        host_header = Headers(
            scope=scope,
        ).get("host", "")

        hostname = (
            urlsplit(
                f"//{host_header}",
            ).hostname
            or ""
        )

        if not self._is_allowed(hostname):
            response = APIResponse.error(
                error_code="UNTRUSTED_HOST",
                message="The request host is not allowed.",
                status_code=400,
            )

            await response(
                scope,
                receive,
                send,
            )
            return

        await self.app(
            scope,
            receive,
            send,
        )


def register_middleware(
    app: FastAPI,
    settings: AppSettings,
) -> None:
    """Register application middleware.

    Starlette makes the last added middleware the outermost wrapper. Request
    context is registered last so every downstream response, including security
    rejections, receives correlation headers.
    """
    app.add_middleware(
        TrustedHostValidationMiddleware,
        enabled=settings.HOST_VALIDATION_ENABLED,
        allowed_hosts=settings.ALLOWED_HOSTS,
    )

    if settings.CORS_ALLOWED_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ALLOWED_ORIGINS,
            allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
            allow_methods=[
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
            ],
            allow_headers=[
                "Accept",
                "Authorization",
                "Content-Type",
                "User-Agent",
                "X-Client-ID",
                "X-Correlation-ID",
                "X-Device-ID",
                "X-Device-Type",
                "X-Forwarded-For",
                "X-Platform",
                "X-Request-ID",
            ],
            expose_headers=[
                "X-API-Version",
                "X-Correlation-ID",
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
                "X-Request-ID",
            ],
            max_age=600,
        )

    app.add_middleware(
        RequestSizeLimitMiddleware,
        max_body_bytes=settings.MAX_REQUEST_BODY_BYTES,
    )

    app.add_middleware(
        SecurityHeadersMiddleware,
        enabled=settings.SECURE_HEADERS_ENABLED,
        hsts_enabled=settings.HSTS_ENABLED,
    )

    app.add_middleware(
        RequestLoggingMiddleware,
        slow_threshold_ms=settings.SLOW_REQUEST_THRESHOLD_MS,
    )

    app.add_middleware(
        RequestContextMiddleware,
        api_version=settings.API_V1_STR,
    )


__all__ = [
    'register_middleware',
    'RequestContextMiddleware',
    'RequestLoggingMiddleware',
    'RequestSizeLimitMiddleware',
    'SecurityHeadersMiddleware',
    'TrustedHostValidationMiddleware',
]
