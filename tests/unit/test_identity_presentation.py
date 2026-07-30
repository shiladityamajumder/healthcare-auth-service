"""File: tests/unit/test_identity_presentation.py

Purpose:
Verifies public profile projection and deterministic display-name fallbacks.

Dependency flow:
Identity/profile values
-> public_user_data()
-> transport-safe user dictionary
-> projection assertions
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.auth.identity.presentation import public_user_data
from app.models.enums import UserStatus


def _user(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
        "email": "ada@example.com",
        "email_verified_at": None,
        "phone_country_code": "+91",
        "phone_number": "9876543210",
        "phone_verified_at": None,
        "status": UserStatus.ACTIVE,
        "preferred_locale": "en-IN",
        "timezone": "Asia/Kolkata",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_public_user_data_projects_profile_and_preferred_display_name() -> None:
    profile = SimpleNamespace(
        first_name="Augusta",
        last_name="Lovelace",
        preferred_name="Ada",
        avatar_object_key="avatars/ada.png",
    )

    result = public_user_data(_user(), profile=profile)

    assert result["display_name"] == "Ada"
    assert result["profile"] == {
        "first_name": "Augusta",
        "last_name": "Lovelace",
        "preferred_name": "Ada",
        "avatar_object_key": "avatars/ada.png",
    }


def test_public_user_data_uses_combined_name_then_identity_fallbacks() -> None:
    profile = SimpleNamespace(
        first_name="Ada",
        last_name="Lovelace",
        preferred_name=None,
        avatar_object_key=None,
    )

    assert public_user_data(_user(), profile=profile)["display_name"] == "Ada Lovelace"
    assert public_user_data(_user(), profile=None)["display_name"] == "ada@example.com"
    assert public_user_data(_user(email=None), profile=None)["display_name"] == "+91******3210"
    assert (
        public_user_data(
            _user(email=None, phone_country_code=None, phone_number=None),
            profile=None,
        )["display_name"]
        == "11111111"
    )
