"""File: tests/unit/test_auth_schemas.py

Purpose:
Verifies non-obvious identity and administrative request validation owned by
vertical module schemas.

Dependency flow:
Test payload
-> Pydantic module schema
-> normalized model or validation error
-> contract assertion
"""

from __future__ import annotations

import pytest
from app.modules.admin_permissions.schemas import (
    CreatePermissionRequest,
    UpdatePermissionRequest,
)
from app.modules.current_user.schemas import UpdateCurrentUserRequest
from app.modules.login.schemas import (
    PasswordLoginRequest,
    PhoneOtpLoginRequest,
    PhoneOtpLoginVerifyRequest,
)
from app.modules.registration.schemas import (
    EmailPasswordRegistrationRequest,
    PhoneOtpRegistrationVerifyRequest,
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


def test_session_device_metadata_is_rejected_from_request_bodies() -> None:
    """Require clients to send session device metadata through headers."""
    with pytest.raises(ValidationError):
        PasswordLoginRequest(
            channel="email",
            email="person@example.com",
            password="StrongPassword!123",  # noqa: S106 - inert test input
            device_id="device-1",  # type: ignore[call-arg]
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


def test_registration_accepts_optional_universal_profile() -> None:
    payload = EmailPasswordRegistrationRequest(
        email="profile@example.com",
        password="StrongPassword!123",  # noqa: S106 - inert test input
        first_name="Ada",
        last_name="Lovelace",
        preferred_name="Ada",
        avatar_object_key="avatars/user.png",
    )

    assert payload.first_name == "Ada"
    assert payload.preferred_name == "Ada"


@pytest.mark.parametrize(
    "role_code",
    [
        "platform_admin",
        "super_admin",
        "custom_privileged_role",
    ],
)
@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (
            EmailPasswordRegistrationRequest,
            {
                "email": "attacker@example.com",
                "password": "StrongPassword!123",
            },
        ),
        (
            PhoneOtpRegistrationVerifyRequest,
            {
                "challenge_id": "11111111-1111-1111-1111-111111111111",
                "phone_country_code": "+91",
                "phone_number": "9876543210",
                "code": "123456",
            },
        ),
    ],
)
def test_public_registration_rejects_client_controlled_roles(
    role_code: str,
    schema: type[EmailPasswordRegistrationRequest] | type[PhoneOtpRegistrationVerifyRequest],
    payload: dict[str, object],
) -> None:
    """Reject privilege-related role input on both public registration flows."""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        schema.model_validate({**payload, "roles": [role_code]})


def test_profile_fields_reject_blank_strings() -> None:
    with pytest.raises(ValidationError):
        UpdateCurrentUserRequest(first_name="   ")


def test_current_user_profile_allows_explicit_field_clear() -> None:
    payload = UpdateCurrentUserRequest(preferred_name=None)

    assert "preferred_name" in payload.model_fields_set
    assert payload.preferred_name is None
