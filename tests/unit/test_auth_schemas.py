"""File: tests/unit/test_auth_schemas.py
Validation tests for endpoint contracts owned by vertical modules."""

from __future__ import annotations

import pytest
from app.modules.admin_permissions.schemas import (
    CreatePermissionRequest,
    UpdatePermissionRequest,
)
from app.modules.login.schemas import (
    PasswordLoginRequest,
    PhoneOtpLoginRequest,
    PhoneOtpLoginVerifyRequest,
)
from pydantic import ValidationError


def test_email_password_login_requires_email() -> None:
    with pytest.raises(ValidationError):
        PasswordLoginRequest(
            channel="email",
            password="StrongPassword!123",  # noqa: S106 - inert test input
        )


def test_phone_password_login_requires_complete_phone() -> None:
    with pytest.raises(ValidationError):
        PasswordLoginRequest(
            channel="phone",
            phone_country_code="+91",
            password="StrongPassword!123",  # noqa: S106 - inert test input
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


def test_permission_master_accepts_normalized_definition() -> None:
    payload = CreatePermissionRequest(
        code="inventory.products.read",
        resource="inventory.products",
        action="read",
        description="Read the product master.",
    )
    assert payload.code == "inventory.products.read"


def test_permission_master_update_requires_at_least_one_field() -> None:
    with pytest.raises(ValidationError):
        UpdatePermissionRequest()


def test_permission_master_update_rejects_null_required_field() -> None:
    with pytest.raises(ValidationError):
        UpdatePermissionRequest(resource=None)
