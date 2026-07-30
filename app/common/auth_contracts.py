"""File: app/common/auth_contracts.py
Reusable, transport-safe response contracts shared by identity modules.

Only stable response envelopes that are genuinely identical across multiple
vertical slices belong here. Each module continues to own its request models
and use-case-specific responses in its local ``schemas.py`` file.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from app.common.schemas import StrictModel


class MessageResponse(StrictModel):
    """Stable message response for commands without a resource body."""

    message: str


class UserResponse(StrictModel):
    """Non-sensitive identity representation returned to API clients."""

    id: uuid.UUID
    email: str | None
    email_verified: bool
    phone_country_code: str | None
    phone_number_masked: str | None
    phone_verified: bool
    status: str
    preferred_locale: str
    timezone: str
    roles: list[str]
    permissions: list[str]


class TokenPairResponse(StrictModel):
    """Access and refresh token pair bound to a persisted session."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"  # noqa: S105
    access_expires_at: datetime
    refresh_expires_at: datetime
    user: UserResponse


class OtpChallengeResponse(StrictModel):
    """Generic OTP issuance response that avoids account enumeration."""

    accepted: bool = True
    challenge_id: uuid.UUID
    expires_at: datetime
    retry_after_seconds: int
    development_otp: str | None = None


__all__ = [
    "MessageResponse",
    "OtpChallengeResponse",
    "TokenPairResponse",
    "UserResponse",
]
