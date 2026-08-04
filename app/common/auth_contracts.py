"""File: app/common/auth_contracts.py

Purpose:
Defines transport-safe response contracts reused unchanged by identity modules.

Dependency flow:
Module service or presentation helper
-> shared StrictModel response type
-> route response_model validation
-> canonical API envelope

Only stable response envelopes that are genuinely identical across multiple
vertical slices belong here. Each module continues to own its request models
and use-case-specific responses in its local ``schemas.py`` file.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import AnyHttpUrl

from app.common.schemas import StrictModel


class MessageResponse(StrictModel):
    """Stable message response for commands without a resource body."""

    message: str


class PublicFileResponse(StrictModel):
    """Client-safe reference to an available public file."""

    id: uuid.UUID
    url: AnyHttpUrl


class UserProfileResponse(StrictModel):
    """Optional human-readable profile attached to an identity."""

    first_name: str | None
    last_name: str | None
    preferred_name: str | None
    avatar: PublicFileResponse | None


class AuthenticatedUserResponse(StrictModel):
    """Minimal authenticated identity profile without authorization lists."""

    id: uuid.UUID
    email: str | None
    email_verified: bool
    phone_country_code: str | None
    phone_number_masked: str | None
    phone_verified: bool
    status: str
    preferred_locale: str
    timezone: str
    display_name: str
    profile: UserProfileResponse | None


class CurrentAuthorizationResponse(StrictModel):
    """Current database-backed global authorization for one principal."""

    roles: list[str]
    permissions: list[str]


class TokenPairResponse(StrictModel):
    """Canonical token response with a minimal authenticated profile."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"  # noqa: S105
    access_expires_at: datetime
    refresh_expires_at: datetime
    user: AuthenticatedUserResponse


class OtpChallengeResponse(StrictModel):
    """Generic OTP issuance response that avoids account enumeration."""

    accepted: bool = True
    challenge_id: uuid.UUID
    expires_at: datetime
    retry_after_seconds: int
    development_otp: str | None = None


__all__ = [
    "AuthenticatedUserResponse",
    "CurrentAuthorizationResponse",
    "MessageResponse",
    "OtpChallengeResponse",
    "PublicFileResponse",
    "TokenPairResponse",
    "UserProfileResponse",
]
