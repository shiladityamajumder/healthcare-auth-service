"""File: app/modules/registration/schemas.py

Purpose:
Defines email/password and phone/OTP registration inputs, initial role lists,
profile fields, and registration responses.

Dependency flow:
HTTP body or service result
-> Pydantic identity, role, and profile validation
-> registration route/service
-> response-model serialization
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import EmailStr, Field, field_validator

from app.common.auth_contracts import (
    OtpChallengeResponse,
    TokenPairResponse,
    UserResponse,
)
from app.common.schemas import StrictModel

RoleCode = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")]


class _RegistrationRoles(StrictModel):
    """Shared initial-role input for workflows that create a user.

    Role codes are used instead of database UUIDs because they form the stable
    public RBAC contract. The service still resolves every code against active
    database records before creating the user.
    """

    roles: list[RoleCode] = Field(default_factory=list, max_length=10)

    @field_validator("roles")
    @classmethod
    def reject_duplicate_roles(cls, values: list[str]) -> list[str]:
        """Reject duplicate codes instead of creating duplicate assignments."""
        if len(values) != len(set(values)):
            raise ValueError("roles must contain unique role codes")
        return values


class _RegistrationProfile(StrictModel):
    """Optional universal profile values accepted during account creation."""

    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    preferred_name: str | None = Field(default=None, min_length=1, max_length=100)
    avatar_object_key: str | None = Field(default=None, min_length=1, max_length=512)


class EmailPasswordRegistrationRequest(
    _RegistrationRoles,
    _RegistrationProfile,
):
    """Email/password registration body with optional initial role codes."""

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
    _RegistrationRoles,
    _RegistrationProfile,
):
    """Phone OTP proof, optional password, and optional initial role codes."""

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
