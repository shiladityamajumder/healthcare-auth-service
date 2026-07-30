"""File: app/modules/registration/schemas.py
Registration request and response contracts owned by this module."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import EmailStr, Field

from app.common.auth_contracts import (
    OtpChallengeResponse,
    TokenPairResponse,
    UserResponse,
)
from app.common.schemas import DeviceContext, StrictModel


class EmailPasswordRegistrationRequest(DeviceContext):
    """Email/password registration body."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    preferred_locale: str = Field(default="en-IN", min_length=2, max_length=16)
    timezone: str = Field(default="Asia/Kolkata", min_length=3, max_length=64)
    terms_version: str | None = Field(default=None, max_length=32)
    privacy_version: str | None = Field(default=None, max_length=32)


class PhoneOtpRegistrationRequest(StrictModel):
    """Phone destination used to request a registration OTP."""

    phone_country_code: str = Field(min_length=1, max_length=8)
    phone_number: str = Field(min_length=6, max_length=32)


class PhoneOtpRegistrationVerifyRequest(DeviceContext):
    """Phone OTP proof and optional initial password."""

    challenge_id: uuid.UUID
    phone_country_code: str = Field(min_length=1, max_length=8)
    phone_number: str = Field(min_length=6, max_length=32)
    code: str = Field(pattern=r"^[0-9]{6}$")
    password: str | None = Field(default=None, min_length=1, max_length=128)
    preferred_locale: str = Field(default="en-IN", min_length=2, max_length=16)
    timezone: str = Field(default="Asia/Kolkata", min_length=3, max_length=64)
    terms_version: str | None = Field(default=None, max_length=32)
    privacy_version: str | None = Field(default=None, max_length=32)


class RegistrationResponse(StrictModel):
    """Registration result with either verification or session information."""

    user: UserResponse
    verification_required: bool
    challenge_id: uuid.UUID | None = None
    expires_at: datetime | None = None
    development_otp: str | None = None
    tokens: TokenPairResponse | None = None


__all__ = [
    "EmailPasswordRegistrationRequest",
    "OtpChallengeResponse",
    "PhoneOtpRegistrationRequest",
    "PhoneOtpRegistrationVerifyRequest",
    "RegistrationResponse",
    "TokenPairResponse",
    "UserResponse",
]
