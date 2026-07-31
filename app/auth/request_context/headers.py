"""File: app/auth/request_context/headers.py

Purpose:
Defines validated, narrowly composed FastAPI header profiles for rate limits,
session creation, and authenticated-principal consistency checks.

Dependency flow:
HTTP headers
-> FastAPI Header validation
-> typed header dataclass dependency
-> AuthRequestContext construction
-> workflow or principal dependency

These headers contain request metadata, not authentication credentials.

``X-User-ID`` and ``X-Session-ID`` are accepted only as optional consistency
assertions. They must match signed access-token claims and can never identify
or authenticate a caller by themselves.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import Header

from app.common.exceptions import ValidationError

_ALLOWED_PLATFORMS: Final[frozenset[str]] = frozenset(
    {
        "web",
        "android",
        "ios",
        "service",
    }
)


@dataclass(frozen=True, slots=True)
class AuthHeaders:
    """Validated authentication and client request metadata."""

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
        Header(
            alias="X-Client-ID",
            min_length=1,
            max_length=128,
            description="Optional client application identifier.",
        ),
    ] = None,
    x_client_version: Annotated[
        str | None,
        Header(
            alias="X-Client-Version",
            min_length=1,
            max_length=64,
            description="Optional client application version.",
        ),
    ] = None,
    x_platform: Annotated[
        str | None,
        Header(
            alias="X-Platform",
            min_length=1,
            max_length=16,
            description=("Client platform: web, android, ios, or service."),
        ),
    ] = None,
    x_device_id: Annotated[
        str | None,
        Header(
            alias="X-Device-ID",
            min_length=1,
            max_length=255,
            description="Optional stable device identifier.",
        ),
    ] = None,
    x_device_type: Annotated[
        str | None,
        Header(
            alias="X-Device-Type",
            min_length=1,
            max_length=32,
        ),
    ] = None,
    x_device_name: Annotated[
        str | None,
        Header(
            alias="X-Device-Name",
            min_length=1,
            max_length=128,
        ),
    ] = None,
    x_user_id: Annotated[
        uuid.UUID | None,
        Header(
            alias="X-User-ID",
            description=(
                "Optional access-token subject consistency assertion. Never authoritative."
            ),
        ),
    ] = None,
    x_session_id: Annotated[
        uuid.UUID | None,
        Header(
            alias="X-Session-ID",
            description=(
                "Optional access-token session consistency assertion. Never authoritative."
            ),
        ),
    ] = None,
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            min_length=8,
            max_length=128,
            description=(
                "Client-generated key used to deduplicate supported state-changing requests."
            ),
        ),
    ] = None,
) -> AuthHeaders:
    """Build validated authentication header metadata.

    FastAPI validates basic declared lengths and UUID syntax. This function
    performs normalization and validation after trimming surrounding
    whitespace.

    Returns:
        Immutable validated header metadata.

    Raises:
        ValidationError: If a header becomes blank after normalization,
            contains control characters, or has an unsupported value.
    """
    platform = _clean_optional_header(
        x_platform,
        header_name="X-Platform",
        min_length=1,
        max_length=16,
        casefold=True,
    )

    if platform is not None and platform not in _ALLOWED_PLATFORMS:
        raise ValidationError("X-Platform must be one of web, android, ios, or service.")

    return AuthHeaders(
        client_id=_clean_optional_header(
            x_client_id,
            header_name="X-Client-ID",
            min_length=1,
            max_length=128,
        ),
        client_version=_clean_optional_header(
            x_client_version,
            header_name="X-Client-Version",
            min_length=1,
            max_length=64,
        ),
        platform=platform,
        device_id=_clean_optional_header(
            x_device_id,
            header_name="X-Device-ID",
            min_length=1,
            max_length=255,
        ),
        device_type=_clean_optional_header(
            x_device_type,
            header_name="X-Device-Type",
            min_length=1,
            max_length=32,
            casefold=True,
        ),
        device_name=_clean_optional_header(
            x_device_name,
            header_name="X-Device-Name",
            min_length=1,
            max_length=128,
        ),
        user_id=x_user_id,
        session_id=x_session_id,
        idempotency_key=_clean_optional_header(
            idempotency_key,
            header_name="Idempotency-Key",
            min_length=8,
            max_length=128,
        ),
    )


def get_rate_limit_headers(
    x_client_id: Annotated[
        str | None,
        Header(
            alias="X-Client-ID",
            min_length=1,
            max_length=128,
            description="Optional client identifier used as a rate-limit dimension.",
        ),
    ] = None,
    x_device_id: Annotated[
        str | None,
        Header(
            alias="X-Device-ID",
            min_length=1,
            max_length=255,
            description="Optional stable device identifier used as a rate-limit dimension.",
        ),
    ] = None,
) -> AuthHeaders:
    """Return only metadata consumed by anonymous rate-limited workflows."""
    return get_auth_headers(
        x_client_id=x_client_id,
        x_device_id=x_device_id,
    )


def get_session_creation_headers(
    x_client_id: Annotated[
        str | None,
        Header(
            alias="X-Client-ID",
            min_length=1,
            max_length=128,
            description="Optional client identifier used as a rate-limit dimension.",
        ),
    ] = None,
    x_platform: Annotated[
        str | None,
        Header(
            alias="X-Platform",
            min_length=1,
            max_length=16,
            description=(
                "Client platform: web, android, ios, or service. Used as the "
                "session device type when X-Device-Type is not supplied."
            ),
        ),
    ] = None,
    x_device_id: Annotated[
        str | None,
        Header(
            alias="X-Device-ID",
            min_length=1,
            max_length=255,
            description=(
                "Optional stable device identifier used as a rate-limit "
                "dimension and persisted on newly issued sessions."
            ),
        ),
    ] = None,
    x_device_type: Annotated[
        str | None,
        Header(
            alias="X-Device-Type",
            min_length=1,
            max_length=32,
            description=(
                "Optional device type persisted on newly issued or rotated sessions."
            ),
        ),
    ] = None,
) -> AuthHeaders:
    """Return metadata consumed by workflows that issue or rotate a session."""
    return get_auth_headers(
        x_client_id=x_client_id,
        x_platform=x_platform,
        x_device_id=x_device_id,
        x_device_type=x_device_type,
    )


def get_principal_assertion_headers(
    x_device_id: Annotated[
        str | None,
        Header(
            alias="X-Device-ID",
            min_length=1,
            max_length=255,
            description=(
                "Optional authenticated-session device consistency assertion. Never authoritative."
            ),
        ),
    ] = None,
    x_user_id: Annotated[
        uuid.UUID | None,
        Header(
            alias="X-User-ID",
            description=(
                "Optional access-token subject consistency assertion. Never authoritative."
            ),
        ),
    ] = None,
    x_session_id: Annotated[
        uuid.UUID | None,
        Header(
            alias="X-Session-ID",
            description=(
                "Optional access-token session consistency assertion. Never authoritative."
            ),
        ),
    ] = None,
) -> AuthHeaders:
    """Return optional assertions checked only after bearer-token validation."""
    return get_auth_headers(
        x_device_id=x_device_id,
        x_user_id=x_user_id,
        x_session_id=x_session_id,
    )


def _clean_optional_header(
    value: str | None,
    *,
    header_name: str,
    min_length: int,
    max_length: int,
    casefold: bool = False,
) -> str | None:
    """Normalize and validate an optional text header."""
    if value is None:
        return None

    normalized = value.strip()

    if len(normalized) < min_length:
        raise ValidationError(f"{header_name} is shorter than the minimum allowed length.")

    if len(normalized) > max_length:
        raise ValidationError(f"{header_name} exceeds the maximum allowed length.")

    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValidationError(f"{header_name} contains invalid control characters.")

    if casefold:
        normalized = normalized.casefold()

    return normalized


__all__ = [
    "AuthHeaders",
    "get_auth_headers",
    "get_principal_assertion_headers",
    "get_rate_limit_headers",
    "get_session_creation_headers",
]
