"""File: tests/unit/test_auth_security.py

Purpose:
Verifies password, HMAC/OTP, JWT/JWKS, token binding, and log-redaction security
primitives.

Dependency flow:
Deterministic test settings and inputs
-> security manager/helper
-> cryptographic output or verification path
-> security invariant assertion
"""

from __future__ import annotations

import base64
import uuid

import jwt
import pytest
from app.auth.request_context.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.auth.security.passwords import PasswordManager
from app.auth.security.tokens import TokenManager, TokenType
from app.auth.workflows.session_tokens import SessionTokenIssuer
from app.common.exceptions import AuthenticationError
from app.core.config import AppSettings
from app.core.logging import sanitize_log_value
from app.models.identity import Sessions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class _SessionWriter:
    """Capture sessions staged by the issuer without a database transaction."""

    def __init__(self) -> None:
        self.sessions: list[Sessions] = []

    def add_session(self, session_record: Sessions) -> None:
        self.sessions.append(session_record)


def auth_settings() -> AppSettings:
    """Build isolated HS256 settings for security tests."""
    return AppSettings(
        _env_file=None,
        POSTGRES_URL="postgresql+asyncpg://user:password@localhost/database",
        AUTH_PEPPER="p" * 64,
        JWT_SECRET="s" * 80,
        OTP_DEV_EXPOSE_CODE=False,
    )


def _resign_hs256(
    settings: AppSettings,
    payload: dict[str, object],
    *,
    key_id: str | None = None,
    algorithm: str = "HS256",
) -> str:
    return jwt.encode(
        payload,
        settings.jwt_secret_value,
        algorithm=algorithm,
        headers={"kid": key_id or settings.JWT_KEY_ID, "typ": "JWT"},
    )


@pytest.mark.asyncio
async def test_password_hash_is_verified_and_rejects_wrong_password() -> None:
    """Protect Argon2 verification for correct and incorrect credentials."""
    manager = PasswordManager(auth_settings())
    password_hash = await manager.hash("StrongPassword!123")
    assert await manager.verify(password_hash, "StrongPassword!123") is True
    assert await manager.verify(password_hash, "WrongPassword!123") is False


def test_access_token_has_expected_type_and_subject() -> None:
    """Require the exact minimal access-token contract."""
    manager = TokenManager(auth_settings())
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    encoded = manager.create_access_token(
        user_id=user_id,
        session_id=session_id,
        auth_methods=["password"],
    )
    payload = manager.decode(encoded.token, expected_type=TokenType.ACCESS)
    assert payload["sub"] == str(user_id)
    assert payload["sid"] == str(session_id)
    assert payload["token_type"] == "access"  # noqa: S105 - token type assertion
    assert uuid.UUID(payload["jti"])
    assert payload["amr"] == ["password"]
    assert set(payload) == {
        "sub",
        "token_type",
        "jti",
        "sid",
        "iat",
        "nbf",
        "exp",
        "iss",
        "aud",
        "amr",
    }
    assert {"user_id", "roles", "permissions", "ver"}.isdisjoint(payload)


@pytest.mark.parametrize(
    ("changed_claim", "changed_value"),
    [
        ("iss", "wrong-issuer"),
        ("aud", "wrong-audience"),
        ("exp", 0),
        ("nbf", 4_102_444_800),
    ],
)
def test_access_token_rejects_wrong_registered_claims(
    changed_claim: str,
    changed_value: object,
) -> None:
    settings = auth_settings()
    manager = TokenManager(settings)
    encoded = manager.create_access_token(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        auth_methods=["password"],
    )
    payload = jwt.decode(encoded.token, options={"verify_signature": False})
    payload[changed_claim] = changed_value

    with pytest.raises(AuthenticationError):
        manager.decode(
            _resign_hs256(settings, payload),
            expected_type=TokenType.ACCESS,
        )


def test_expired_refresh_token_and_malformed_jwt_are_rejected() -> None:
    settings = auth_settings()
    manager = TokenManager(settings)
    refresh = manager.create_refresh_token(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        family_id=uuid.uuid4(),
    )
    payload = jwt.decode(refresh.token, options={"verify_signature": False})
    payload["exp"] = 0

    with pytest.raises(AuthenticationError):
        manager.decode(
            _resign_hs256(settings, payload),
            expected_type=TokenType.REFRESH,
        )
    with pytest.raises(AuthenticationError):
        manager.decode("not-a-jwt", expected_type=TokenType.ACCESS)


def test_algorithm_and_key_identifier_confusion_are_rejected() -> None:
    settings = auth_settings()
    manager = TokenManager(settings)
    encoded = manager.create_access_token(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        auth_methods=["password"],
    )
    payload = jwt.decode(encoded.token, options={"verify_signature": False})

    with pytest.raises(AuthenticationError):
        manager.decode(
            _resign_hs256(settings, payload, algorithm="HS384"),
            expected_type=TokenType.ACCESS,
        )
    with pytest.raises(AuthenticationError):
        manager.decode(
            _resign_hs256(settings, payload, key_id="unknown-key"),
            expected_type=TokenType.ACCESS,
        )


@pytest.mark.parametrize(
    ("claim_name", "claim_value"),
    [
        ("roles", ["platform_admin"]),
        ("permissions", ["identity.users.manage"]),
        ("user_id", "11111111-1111-1111-1111-111111111111"),
        ("ver", 1),
        ("email", "attacker@example.com"),
    ],
)
def test_access_token_rejects_any_injected_claim(
    claim_name: str,
    claim_value: object,
) -> None:
    """Fail closed when a signed access token exceeds the canonical schema."""
    settings = auth_settings()
    manager = TokenManager(settings)
    encoded = manager.create_access_token(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        auth_methods=["password"],
    )
    payload = jwt.decode(encoded.token, options={"verify_signature": False})
    payload[claim_name] = claim_value

    with pytest.raises(AuthenticationError):
        manager.decode(
            _resign_hs256(settings, payload),
            expected_type=TokenType.ACCESS,
        )


def test_access_token_requires_at_least_one_authentication_method() -> None:
    with pytest.raises(ValueError, match="at least one value"):
        TokenManager(auth_settings()).create_access_token(
            user_id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            auth_methods=[],
        )


@pytest.mark.parametrize(
    "missing_claim",
    ["sub", "token_type", "jti", "sid", "iat", "nbf", "exp", "iss", "aud", "amr"],
)
def test_access_token_rejects_missing_mandatory_claim(
    missing_claim: str,
) -> None:
    """Reject every incomplete access-token contract."""
    settings = auth_settings()
    manager = TokenManager(settings)
    encoded = manager.create_access_token(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        auth_methods=["password"],
    )
    payload = jwt.decode(encoded.token, options={"verify_signature": False})
    payload.pop(missing_claim)
    incomplete_token = jwt.encode(
        payload,
        settings.jwt_secret_value,
        algorithm=settings.JWT_ALGORITHM.value,
        headers={"kid": settings.JWT_KEY_ID, "typ": "JWT"},
    )

    with pytest.raises(AuthenticationError):
        manager.decode(incomplete_token, expected_type=TokenType.ACCESS)


def test_refresh_token_has_exact_minimal_contract() -> None:
    settings = auth_settings()
    manager = TokenManager(settings)
    encoded = manager.create_refresh_token(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        family_id=uuid.uuid4(),
    )
    payload = manager.decode(encoded.token, expected_type=TokenType.REFRESH)
    assert set(payload) == {
        "sub",
        "token_type",
        "jti",
        "sid",
        "fam",
        "iat",
        "nbf",
        "exp",
        "iss",
        "aud",
    }
    assert {"user_id", "roles", "permissions", "ver", "amr"}.isdisjoint(payload)

    payload["roles"] = ["platform_admin"]
    with pytest.raises(AuthenticationError):
        manager.decode(
            _resign_hs256(settings, payload),
            expected_type=TokenType.REFRESH,
        )


@pytest.mark.parametrize(
    ("device_type", "platform", "expected_device_type"),
    [
        ("phone", "android", "phone"),
        (None, "ios", "ios"),
    ],
)
def test_session_issuer_uses_header_context_for_device_metadata(
    device_type: str | None,
    platform: str,
    expected_device_type: str,
) -> None:
    """Persist validated header metadata, preferring device type to platform."""
    writer = _SessionWriter()
    issuer = SessionTokenIssuer(
        tokens=TokenManager(auth_settings()),
        hashing=SecureHashing(auth_settings()),
    )

    issuer.issue(
        user_id=uuid.uuid4(),
        session_writer=writer,
        request_context=AuthRequestContext(
            platform=platform,
            device_id="header-device",
            device_type=device_type,
        ),
        auth_methods=["password"],
    )

    assert writer.sessions[0].device_id == "header-device"
    assert writer.sessions[0].device_type == expected_device_type


def test_password_reset_proof_is_bound_to_challenge_and_token_type() -> None:
    """Keep reset proofs bound to their challenge and non-access token type."""
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
    """Verify configured RSA signing and public JWKS verification metadata."""
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
    """Prevent authentication secrets from surviving structured log redaction."""
    sanitized = sanitize_log_value(
        {
            "access_token": "eyJaccess.payload.signature",
            "authorization": "Bearer eyJheader.payload.signature",
            "client_secret": "sk_sensitive",
            "otp_code": "123456",
            "password": "StrongPassword!123",
            "refresh_token": "raw-refresh-token",
            "reset_token": "eyJabc.def.ghi",
            "session_secret": "session-secret",
            "verification_token": "verification-secret",
            "nested": {"password_hash": "argon2-hash"},
        }
    )
    assert sanitized["access_token"] == "[REDACTED]"  # noqa: S105
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["client_secret"] == "[REDACTED]"  # noqa: S105
    assert sanitized["otp_code"] == "[REDACTED]"
    assert sanitized["password"] == "[REDACTED]"  # noqa: S105
    assert sanitized["refresh_token"] == "[REDACTED]"  # noqa: S105
    assert sanitized["reset_token"] == "[REDACTED_JWT]"  # noqa: S105
    assert sanitized["session_secret"] == "[REDACTED]"  # noqa: S105
    assert sanitized["verification_token"] == "[REDACTED]"  # noqa: S105
    assert sanitized["nested"]["password_hash"] == "[REDACTED]"  # noqa: S105


def test_otp_hash_verification_uses_challenge_binding() -> None:
    """Ensure an OTP digest cannot be replayed against another challenge ID."""
    hashing = SecureHashing(auth_settings())
    challenge_id = uuid.uuid4()
    expected = hashing.otp_hash(challenge_id, "123456")

    assert hashing.verify_otp_hash(challenge_id, "123456", expected) is True
    assert hashing.verify_otp_hash(uuid.uuid4(), "123456", expected) is False
