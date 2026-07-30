"""File: app/core/request_context.py
    Request-scoped observability context based on ``contextvars``.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_correlation_id: ContextVar[str | None] = ContextVar(
    "correlation_id", default=None
)
_trace_id: ContextVar[str | None] = ContextVar("trace_id", default=None)
_api_version: ContextVar[str] = ContextVar("api_version", default="v1")


@dataclass(frozen=True, slots=True)
class RequestContextTokens:
    """Tokens required to restore the previous execution context."""

    request_id: Token[str | None]
    correlation_id: Token[str | None]
    trace_id: Token[str | None]
    api_version: Token[str]


def set_request_context(
    *,
    request_id: str,
    correlation_id: str,
    trace_id: str | None,
    api_version: str,
) -> RequestContextTokens:
    """Bind request metadata to the current asynchronous execution context."""
    if not request_id.strip() or not correlation_id.strip():
        raise ValueError("request and correlation identifiers must be non-empty")

    return RequestContextTokens(
        request_id=_request_id.set(request_id),
        correlation_id=_correlation_id.set(correlation_id),
        trace_id=_trace_id.set(trace_id),
        api_version=_api_version.set(api_version),
    )


def reset_request_context(tokens: RequestContextTokens) -> None:
    """Restore all context variables to their previous values."""
    _api_version.reset(tokens.api_version)
    _trace_id.reset(tokens.trace_id)
    _correlation_id.reset(tokens.correlation_id)
    _request_id.reset(tokens.request_id)


def set_request_id(request_id: str) -> Token[str | None]:
    """Set only the request identifier for background or compatibility code."""
    if not request_id.strip():
        raise ValueError("request_id must be non-empty")
    return _request_id.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    """Reset a request identifier token created by :func:`set_request_id`."""
    _request_id.reset(token)


def get_request_id(default: str | None = None) -> str | None:
    """Return the current request identifier."""
    return _request_id.get() or default


def get_correlation_id(default: str | None = None) -> str | None:
    """Return the current cross-service correlation identifier."""
    return _correlation_id.get() or default


def get_trace_id(default: str | None = None) -> str | None:
    """Return the current W3C trace identifier when present."""
    return _trace_id.get() or default


def get_api_version() -> str:
    """Return the API version bound by request middleware."""
    return _api_version.get()


__all__ = [
    "RequestContextTokens",
    "get_api_version",
    "get_correlation_id",
    "get_request_id",
    "get_trace_id",
    "reset_request_context",
    "reset_request_id",
    "set_request_context",
    "set_request_id",
]
