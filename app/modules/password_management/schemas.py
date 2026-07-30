"""File: app/modules/password_management/schemas.py

Purpose:
Defines mutually exclusive recovery identities, reset proofs, and authenticated
password change/set contracts.

Dependency flow:
HTTP body or service proof result
-> Pydantic identity/password/device validation
-> password route/service
-> response-model serialization
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import EmailStr, Field, model_validator

from app.common.auth_contracts import (
    OtpChallengeResponse,
    TokenPairResponse,
    UserResponse,
)
from app.common.schemas import DeviceContext, StrictModel


class IdentityRequest(StrictModel):
    """Email or phone identity used by password recovery."""

    channel: str = Field(pattern=r"^(email|sms)$")
    email: EmailStr | None = None
    phone_country_code: str | None = Field(default=None, max_length=8)
    phone_number: str | None = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def validate_destination(self) -> IdentityRequest:
        """Require the destination fields selected by the recovery channel."""
        if self.channel == "email" and self.email is None:
            raise ValueError("email is required for the email channel")
        if self.channel == "sms" and (not self.phone_country_code or not self.phone_number):
            raise ValueError("phone_country_code and phone_number are required for SMS")
        return self


class ForgotPasswordRequest(IdentityRequest):
    """Identity used to request a password-reset OTP."""


class VerifyResetOtpRequest(IdentityRequest):
    """OTP proof used to obtain a one-time reset token."""

    challenge_id: uuid.UUID
    code: str = Field(pattern=r"^[0-9]{6}$")


class ResetPasswordProofResponse(StrictModel):
    """Short-lived one-time signed password-reset proof."""

    reset_token: str
    expires_at: datetime


class ResetPasswordWithTokenRequest(DeviceContext):
    """Final password reset request using a signed proof."""

    reset_token: str = Field(min_length=32, max_length=4096)
    new_password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(DeviceContext):
    """Authenticated password change request."""

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class SetPasswordRequest(DeviceContext):
    """Initial password for an OTP-only account."""

    new_password: str = Field(min_length=1, max_length=128)


__all__ = [
    "ChangePasswordRequest",
    "ForgotPasswordRequest",
    "IdentityRequest",
    "OtpChallengeResponse",
    "ResetPasswordProofResponse",
    "ResetPasswordWithTokenRequest",
    "SetPasswordRequest",
    "TokenPairResponse",
    "UserResponse",
    "VerifyResetOtpRequest",
]
