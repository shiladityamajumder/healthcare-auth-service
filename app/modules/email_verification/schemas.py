"""File: app/modules/email_verification/schemas.py

Purpose:
Defines email-verification request/confirmation inputs and token-bearing result
contracts.

Dependency flow:
HTTP body or service result
-> strict Pydantic validation
-> email-verification route/service
-> response-model serialization
"""

from __future__ import annotations

import uuid

from pydantic import EmailStr, Field

from app.common.auth_contracts import (
    OtpChallengeResponse,
    TokenPairResponse,
    UserResponse,
)
from app.common.schemas import StrictModel


class EmailVerificationRequest(StrictModel):
    """Email destination used to issue a verification OTP."""

    email: EmailStr


class EmailVerificationConfirmRequest(StrictModel):
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
