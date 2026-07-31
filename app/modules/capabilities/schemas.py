"""Client-safe anonymous authentication capability contracts."""

from __future__ import annotations

from app.common.schemas import StrictModel
from pydantic import Field


class RegistrationCapabilities(StrictModel):
    email_enabled: bool
    phone_enabled: bool


class LoginCapabilities(StrictModel):
    password_enabled: bool
    phone_otp_enabled: bool


class VerificationCapabilities(StrictModel):
    email_required: bool
    phone_required: bool


class PasswordPolicyCapabilities(StrictModel):
    minimum_length: int
    minimum_character_classes: int


class AuthCapabilitiesResponse(StrictModel):
    """Safe pre-authentication client configuration."""

    schema_name: str = Field(default="auth-capabilities", alias="schema")
    registration: RegistrationCapabilities
    login: LoginCapabilities
    verification: VerificationCapabilities
    password_policy: PasswordPolicyCapabilities
    supported_platforms: list[str]


__all__ = ["AuthCapabilitiesResponse"]
