"""Email-verification contracts owned by this module."""

from __future__ import annotations

import uuid

from pydantic import EmailStr, Field

from app.common.auth_contracts import (
    OtpChallengeResponse,
    TokenPairResponse,
    UserResponse,
)
from app.common.schemas import DeviceContext, StrictModel


class EmailVerificationRequest(StrictModel):
    """Email destination used to issue a verification OTP."""

    email: EmailStr


class EmailVerificationConfirmRequest(DeviceContext):
    """Email verification OTP proof."""

    challenge_id: uuid.UUID
    email: EmailStr
    code: str = Field(pattern=r"^[0-9]{6}$")


__all__ = [
    "EmailVerificationConfirmRequest",
    "EmailVerificationRequest",
    "OtpChallengeResponse",
    "TokenPairResponse",
    "UserResponse",
]
