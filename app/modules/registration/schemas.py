"""File: app/modules/registration/schemas.py

Purpose:
Defines email/password and phone/OTP registration inputs, optional profile
fields, and registration responses.

Dependency flow:
HTTP body or service result
-> Pydantic identity, role, and profile validation
-> registration route/service
-> response-model serialization
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import EmailStr, Field

from app.common.auth_contracts import (
    AuthenticatedUserResponse,
    OtpChallengeResponse,
    TokenPairResponse,
)
from app.common.schemas import StrictModel


class _RegistrationProfile(StrictModel):
    """Optional universal profile values accepted during account creation."""

    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    preferred_name: str | None = Field(default=None, min_length=1, max_length=100)
    avatar_object_key: str | None = Field(default=None, min_length=1, max_length=512)


class EmailPasswordRegistrationRequest(
    _RegistrationProfile,
):
    """Public email/password registration body.

    Role assignment is deliberately absent. ``StrictModel`` rejects a supplied
    ``roles`` property instead of silently accepting privilege-related input.
    """

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


class PhoneOtpRegistrationVerifyRequest(
    _RegistrationProfile,
):
    """Public phone OTP proof and optional initial password/profile."""

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

    user: AuthenticatedUserResponse
    verification_required: bool
    challenge_id: uuid.UUID | None = None
    expires_at: datetime | None = None
    development_otp: str | None = None
    tokens: TokenPairResponse | None = None


__all__ = [
    "AuthenticatedUserResponse",
    "EmailPasswordRegistrationRequest",
    "OtpChallengeResponse",
    "PhoneOtpRegistrationRequest",
    "PhoneOtpRegistrationVerifyRequest",
    "RegistrationResponse",
    "TokenPairResponse",
]
