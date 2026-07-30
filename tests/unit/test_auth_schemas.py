"""File: tests/unit/test_auth_schemas.py
Validation tests for endpoint contracts owned by vertical modules."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.modules.login.schemas import (
    PasswordLoginRequest,
    PhoneOtpLoginRequest,
    PhoneOtpLoginVerifyRequest,
)


def test_email_password_login_requires_email() -> None:
    with pytest.raises(ValidationError):
        PasswordLoginRequest(channel="email", password="StrongPassword!123")


def test_phone_password_login_requires_complete_phone() -> None:
    with pytest.raises(ValidationError):
        PasswordLoginRequest(
            channel="phone",
            phone_country_code="+91",
            password="StrongPassword!123",
        )


def test_phone_otp_request_accepts_complete_destination() -> None:
    payload = PhoneOtpLoginRequest(
        phone_country_code="+91",
        phone_number="9876543210",
    )
    assert payload.phone_number == "9876543210"


def test_phone_otp_verify_rejects_non_numeric_code() -> None:
    with pytest.raises(ValidationError):
        PhoneOtpLoginVerifyRequest(
            challenge_id="11111111-1111-1111-1111-111111111111",
            phone_country_code="+91",
            phone_number="9876543210",
            code="ABC123",
        )
