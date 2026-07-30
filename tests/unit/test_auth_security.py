"""File: tests/unit/test_auth_security.py
Unit tests for password, hashing, and JWT security primitives."""

from __future__ import annotations

import base64
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth.security.hashing import SecureHashing
from app.auth.security.passwords import PasswordManager
from app.auth.security.tokens import TokenManager, TokenType
from app.common.exceptions import AuthenticationError
from app.core.config import AppSettings
from app.core.logging import sanitize_log_value


def auth_settings() -> AppSettings:
    """Build isolated HS256 settings for security tests."""
    return AppSettings(
        _env_file=None,
        POSTGRES_URL="postgresql+asyncpg://user:password@localhost/database",
        AUTH_PEPPER="p" * 64,
        JWT_SECRET="s" * 80,
        OTP_DEV_EXPOSE_CODE=False,
    )


@pytest.mark.asyncio
async def test_password_hash_is_verified_and_rejects_wrong_password() -> None:
    manager = PasswordManager(auth_settings())
    password_hash = await manager.hash("StrongPassword!123")
    assert await manager.verify(password_hash, "StrongPassword!123") is True
    assert await manager.verify(password_hash, "WrongPassword!123") is False


def test_access_token_has_expected_type_and_subject() -> None:
    manager = TokenManager(auth_settings())
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    encoded = manager.create_access_token(
        user_id=user_id,
        session_id=session_id,
        roles=["customer"],
        permissions=["orders.read"],
        auth_methods=["password"],
    )
    payload = manager.decode(encoded.token, expected_type=TokenType.ACCESS)
    assert payload["sub"] == str(user_id)
    assert payload["sid"] == str(session_id)
    assert payload["permissions"] == ["orders.read"]


def test_password_reset_proof_is_bound_to_challenge_and_token_type() -> None:
    manager = TokenManager(auth_settings())
    user_id = uuid.uuid4()
    challenge_id = uuid.uuid4()
    encoded = manager.create_password_reset_token(
        user_id=user_id,
        challenge_id=challenge_id,
        channel="email",
        destination_hash="destination-hash",
    )

    payload = manager.decode(
        encoded.token,
        expected_type=TokenType.PASSWORD_RESET,
    )

    assert payload["sub"] == str(user_id)
    assert payload["challenge_id"] == str(challenge_id)
    assert payload["channel"] == "email"
    assert payload["destination_hash"] == "destination-hash"

    with pytest.raises(AuthenticationError):
        manager.decode(encoded.token, expected_type=TokenType.ACCESS)


def test_rs256_access_token_and_jwks_round_trip() -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    settings = AppSettings(
        _env_file=None,
        POSTGRES_URL="postgresql+asyncpg://user:password@localhost/database",
        AUTH_PEPPER="p" * 64,
        JWT_ALGORITHM="RS256",
        JWT_PRIVATE_KEY_B64=base64.b64encode(private_pem).decode("ascii"),
        JWT_PUBLIC_KEY_B64=base64.b64encode(public_pem).decode("ascii"),
        JWT_KEY_ID="test-key",
    )
    manager = TokenManager(settings)
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    encoded = manager.create_access_token(
        user_id=user_id,
        session_id=session_id,
        roles=["customer"],
        permissions=["catalog.read"],
        auth_methods=["password"],
    )
    payload = manager.decode(encoded.token, expected_type=TokenType.ACCESS)
    assert payload["sub"] == str(user_id)
    assert payload["sid"] == str(session_id)

    jwks = manager.public_jwks()
    assert jwks[0]["kid"] == "test-key"
    assert jwks[0]["alg"] == "RS256"
    assert jwks[0]["n"]
    assert jwks[0]["e"]


def test_authentication_secrets_are_redacted_from_structured_logs() -> None:
    sanitized = sanitize_log_value(
        {
            "client_secret": "sk_sensitive",
            "otp_code": "123456",
            "reset_token": "eyJabc.def.ghi",
            "nested": {"password_hash": "argon2-hash"},
        }
    )
    assert sanitized["client_secret"] == "[REDACTED]"
    assert sanitized["otp_code"] == "[REDACTED]"
    assert sanitized["reset_token"] == "[REDACTED_JWT]"
    assert sanitized["nested"]["password_hash"] == "[REDACTED]"


def test_otp_hash_verification_uses_challenge_binding() -> None:
    hashing = SecureHashing(auth_settings())
    challenge_id = uuid.uuid4()
    expected = hashing.otp_hash(challenge_id, "123456")

    assert hashing.verify_otp_hash(challenge_id, "123456", expected) is True
    assert hashing.verify_otp_hash(uuid.uuid4(), "123456", expected) is False
