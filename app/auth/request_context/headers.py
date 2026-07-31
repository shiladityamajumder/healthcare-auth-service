"""Validated custom-header profiles used by authentication workflows.

Only rate-limit dimensions and session-lifecycle metadata are accepted here.
Authenticated user and session identity always come from signed JWT claims.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import Header

from app.common.exceptions import ValidationError

_ALLOWED_PLATFORMS: Final[frozenset[str]] = frozenset({"web", "android", "ios", "service"})


@dataclass(frozen=True, slots=True)
class AuthHeaders:
    """Validated non-credential request metadata."""

    client_id: str | None = None
    platform: str | None = None
    device_id: str | None = None
    device_type: str | None = None


def get_rate_limit_headers(
    x_client_id: Annotated[
        str | None,
        Header(
            alias="X-Client-ID",
            min_length=1,
            max_length=128,
            description="Optional client identifier used for rate limiting.",
        ),
    ] = None,
    x_device_id: Annotated[
        str | None,
        Header(
            alias="X-Device-ID",
            min_length=1,
            max_length=255,
            description="Optional device rate-limit dimension.",
        ),
    ] = None,
) -> AuthHeaders:
    """Return metadata consumed by anonymous authentication rate limits."""
    return AuthHeaders(
        client_id=_clean_optional_header(
            x_client_id,
            header_name="X-Client-ID",
            max_length=128,
        ),
        device_id=_clean_optional_header(
            x_device_id,
            header_name="X-Device-ID",
            max_length=255,
        ),
    )


def get_session_creation_headers(
    x_client_id: Annotated[
        str | None,
        Header(
            alias="X-Client-ID",
            min_length=1,
            max_length=128,
            description="Optional client identifier used for rate limiting.",
        ),
    ] = None,
    x_platform: Annotated[
        str | None,
        Header(
            alias="X-Platform",
            min_length=1,
            max_length=16,
            description="Optional platform: web, android, ios, or service.",
        ),
    ] = None,
    x_device_id: Annotated[
        str | None,
        Header(
            alias="X-Device-ID",
            min_length=1,
            max_length=255,
            description="Optional device identifier persisted on session creation.",
        ),
    ] = None,
    x_device_type: Annotated[
        str | None,
        Header(
            alias="X-Device-Type",
            min_length=1,
            max_length=32,
            description="Optional device type persisted on session creation.",
        ),
    ] = None,
) -> AuthHeaders:
    """Return metadata allowed when a workflow creates a session."""
    platform = _clean_optional_header(
        x_platform,
        header_name="X-Platform",
        max_length=16,
        casefold=True,
    )
    if platform is not None and platform not in _ALLOWED_PLATFORMS:
        raise ValidationError("X-Platform must be one of web, android, ios, or service.")
    return AuthHeaders(
        client_id=_clean_optional_header(
            x_client_id,
            header_name="X-Client-ID",
            max_length=128,
        ),
        platform=platform,
        device_id=_clean_optional_header(
            x_device_id,
            header_name="X-Device-ID",
            max_length=255,
        ),
        device_type=_clean_optional_header(
            x_device_type,
            header_name="X-Device-Type",
            max_length=32,
            casefold=True,
        ),
    )


def get_refresh_headers(
    x_client_id: Annotated[
        str | None,
        Header(
            alias="X-Client-ID",
            min_length=1,
            max_length=128,
            description="Optional client identifier used for rate limiting.",
        ),
    ] = None,
    x_device_id: Annotated[
        str | None,
        Header(
            alias="X-Device-ID",
            min_length=1,
            max_length=255,
            description="Optional assertion against the stored session device.",
        ),
    ] = None,
) -> AuthHeaders:
    """Return the only custom metadata accepted during refresh."""
    return get_rate_limit_headers(
        x_client_id=x_client_id,
        x_device_id=x_device_id,
    )


def get_principal_headers() -> AuthHeaders:
    """Return an empty profile for bearer-protected endpoints."""
    return AuthHeaders()


def _clean_optional_header(
    value: str | None,
    *,
    header_name: str,
    max_length: int,
    casefold: bool = False,
) -> str | None:
    """Normalize and reject blank or control-character header values."""
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        raise ValidationError(f"{header_name} must not be blank.")
    if len(normalized) > max_length:
        raise ValidationError(f"{header_name} exceeds the maximum allowed length.")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValidationError(f"{header_name} contains invalid control characters.")
    return normalized.casefold() if casefold else normalized


__all__ = [
    "AuthHeaders",
    "get_principal_headers",
    "get_rate_limit_headers",
    "get_refresh_headers",
    "get_session_creation_headers",
]
