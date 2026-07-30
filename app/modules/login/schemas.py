"""File: app/modules/login/schemas.py
Password and phone-OTP login contracts owned by this module."""

from __future__ import annotations

import uuid

from pydantic import EmailStr, Field, model_validator

from app.common.auth_contracts import (
    OtpChallengeResponse,
    TokenPairResponse,
    UserResponse,
)
from app.common.schemas import DeviceContext, StrictModel


class PasswordLoginRequest(DeviceContext):
    """Unified password login body supporting email or phone identities."""

    channel: str = Field(pattern=r"^(email|phone)$")
    email: EmailStr | None = None
    phone_country_code: str | None = Field(default=None, max_length=8)
    phone_number: str | None = Field(default=None, max_length=32)
    password: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_identity(self) -> "PasswordLoginRequest":
        """Require the destination fields selected by the login channel."""
        if self.channel == "email" and self.email is None:
            raise ValueError("email is required for email password login")
        if self.channel == "phone" and (
            not self.phone_country_code or not self.phone_number
        ):
            raise ValueError(
                "phone_country_code and phone_number are required for phone login"
            )
        return self


class PhoneOtpLoginRequest(StrictModel):
    """Phone destination used to request a login OTP."""

    phone_country_code: str = Field(min_length=1, max_length=8)
    phone_number: str = Field(min_length=6, max_length=32)


class PhoneOtpLoginVerifyRequest(DeviceContext):
    """Phone OTP proof used to create a session."""

    challenge_id: uuid.UUID
    phone_country_code: str = Field(min_length=1, max_length=8)
    phone_number: str = Field(min_length=6, max_length=32)
    code: str = Field(pattern=r"^[0-9]{6}$")


__all__ = [
    "OtpChallengeResponse",
    "PasswordLoginRequest",
    "PhoneOtpLoginRequest",
    "PhoneOtpLoginVerifyRequest",
    "TokenPairResponse",
    "UserResponse",
]
