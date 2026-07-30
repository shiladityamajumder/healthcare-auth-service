"""File: tests/unit/test_auth_policy.py

Purpose:
Verifies shared identity normalization, password policy, token-type separation,
and hashing namespace invariants.

Dependency flow:
Test input
-> authentication policy/security helper
-> normalized result or expected rejection
-> invariant assertion
"""

from __future__ import annotations

import uuid

import pytest

from app.auth.identity.normalization import normalize_email, normalize_phone
from app.auth.security.hashing import SecureHashing
from app.auth.security.passwords import PasswordManager
from app.auth.security.tokens import TokenManager, TokenType
from app.common.exceptions import AuthenticationError, ValidationError
from app.core.config import AppSettings


def settings() -> AppSettings:
    """Build isolated authentication settings for policy tests."""
    return AppSettings(
        _env_file=None,
        POSTGRES_URL="postgresql+asyncpg://user:password@localhost/database",
        AUTH_PEPPER="p" * 64,
        JWT_SECRET="s" * 80,
    )


def test_email_and_phone_normalization() -> None:
    assert normalize_email(" User@Example.COM ") == "user@example.com"
    assert normalize_phone("91", "98765-43210") == ("+91", "9876543210")


def test_phone_number_must_not_repeat_country_code() -> None:
    with pytest.raises(ValidationError):
        normalize_phone("+91", "+919876543210")


def test_password_rejects_email_username() -> None:
    manager = PasswordManager(settings())
    with pytest.raises(ValidationError):
        manager.validate_strength(
            "Animesh!Secure123",
            email="animesh@example.com",
        )


def test_token_types_are_not_interchangeable() -> None:
    tokens = TokenManager(settings())
    refresh = tokens.create_refresh_token(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        family_id=uuid.uuid4(),
    )
    with pytest.raises(AuthenticationError):
        tokens.decode(refresh.token, expected_type=TokenType.ACCESS)


def test_peppered_hashes_are_namespaced() -> None:
    hashing = SecureHashing(settings())
    value = "same-value"
    assert hashing.token_hash(value) != hashing.destination_hash(value)
    assert hashing.token_hash(value) == hashing.token_hash(value)
