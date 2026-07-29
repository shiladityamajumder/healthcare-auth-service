"""Typed authentication and client metadata headers.

Headers are metadata, not credentials. ``X-User-ID`` and ``X-Session-ID`` are
accepted only as optional consistency assertions and must match signed JWT
claims. The server never trusts either header to identify a caller.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Header


@dataclass(frozen=True, slots=True)
class AuthHeaders:
    """Validated request metadata used by identity workflows."""

    client_id: str | None = None
    client_version: str | None = None
    platform: str | None = None
    device_id: str | None = None
    device_type: str | None = None
    device_name: str | None = None
    user_id: uuid.UUID | None = None
    session_id: uuid.UUID | None = None
    idempotency_key: str | None = None


def get_auth_headers(
    x_client_id: Annotated[
        str | None,
        Header(alias="X-Client-ID", min_length=1, max_length=128),
    ] = None,
    x_client_version: Annotated[
        str | None,
        Header(alias="X-Client-Version", min_length=1, max_length=64),
    ] = None,
    x_platform: Annotated[
        str | None,
        Header(alias="X-Platform", min_length=1, max_length=16),
    ] = None,
    x_device_id: Annotated[
        str | None,
        Header(alias="X-Device-ID", min_length=1, max_length=255),
    ] = None,
    x_device_type: Annotated[
        str | None,
        Header(alias="X-Device-Type", min_length=1, max_length=32),
    ] = None,
    x_device_name: Annotated[
        str | None,
        Header(alias="X-Device-Name", min_length=1, max_length=128),
    ] = None,
    x_user_id: Annotated[
        uuid.UUID | None,
        Header(
            alias="X-User-ID",
            description="Optional JWT subject consistency assertion. Never authoritative.",
        ),
    ] = None,
    x_session_id: Annotated[
        uuid.UUID | None,
        Header(
            alias="X-Session-ID",
            description="Optional JWT session consistency assertion. Never authoritative.",
        ),
    ] = None,
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key", min_length=8, max_length=128),
    ] = None,
) -> AuthHeaders:
    """Build sanitized header metadata for dependency injection.

    FastAPI validates length and UUID syntax before a route is executed. Values
    are stripped here so downstream services never receive whitespace-only
    identifiers.
    """

    def clean(value: str | None) -> str | None:
        """Normalize an optional request-header value."""
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    platform = clean(x_platform)
    if platform is not None:
        platform = platform.casefold()

    return AuthHeaders(
        client_id=clean(x_client_id),
        client_version=clean(x_client_version),
        platform=platform,
        device_id=clean(x_device_id),
        device_type=clean(x_device_type),
        device_name=clean(x_device_name),
        user_id=x_user_id,
        session_id=x_session_id,
        idempotency_key=clean(idempotency_key),
    )


__all__ = ["AuthHeaders", "get_auth_headers"]
