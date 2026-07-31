"""File: tests/unit/test_configuration.py

Purpose:
Verifies configuration parsing and fail-closed production/infrastructure
cross-field rules.

Dependency flow:
Settings override mapping
-> AppSettings validation
-> accepted configuration or ValidationError
-> security assertion
"""

from __future__ import annotations

import base64

import pytest
from app.core.config import AppSettings, Environment
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

BASE = {
    "_env_file": None,
    "POSTGRES_URL": "postgresql+asyncpg://user:password@localhost/database",
    "AUTH_PEPPER": "p" * 64,
    "JWT_SECRET": "s" * 80,
}


def _rsa_settings() -> dict[str, object]:
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
    return {
        "JWT_ALGORITHM": "RS256",
        "JWT_SECRET": None,
        "JWT_PRIVATE_KEY_B64": base64.b64encode(private_pem).decode("ascii"),
        "JWT_PUBLIC_KEY_B64": base64.b64encode(public_pem).decode("ascii"),
    }


def test_single_configuration_accepts_postgresql_development() -> None:
    """Accept a valid development configuration with PostgreSQL persistence."""
    settings = AppSettings(**BASE)
    assert settings.postgres_url_value.startswith("postgresql+asyncpg://")
    assert settings.auth_pepper_value == "p" * 64


def test_non_async_postgresql_url_is_rejected() -> None:
    """Reject database URLs incompatible with the async SQLAlchemy adapter."""
    with pytest.raises(ValidationError):
        AppSettings(**{**BASE, "POSTGRES_URL": "postgresql://user:pass@localhost/db"})


def test_production_rejects_symmetric_jwt() -> None:
    """Keep production token signing on the required asymmetric algorithm."""
    with pytest.raises(ValidationError):
        AppSettings(
            **{
                **BASE,
                "ENVIRONMENT": Environment.PRODUCTION,
                "DOCS_ENABLED": False,
                "LOG_JSON": True,
                "SECURE_HEADERS_ENABLED": True,
                "HSTS_ENABLED": True,
                "HOST_VALIDATION_ENABLED": True,
                "ALLOWED_HOSTS": ["identity.example.com"],
            }
        )


def test_production_rejects_disabled_rate_limiting_explicitly() -> None:
    """Fail closed when production attempts to disable rate limiting."""
    with pytest.raises(
        ValidationError,
        match="Production cannot use RATE_LIMIT_BACKEND=disabled",
    ):
        AppSettings(
            **{
                **BASE,
                "ENVIRONMENT": Environment.PRODUCTION,
                "RATE_LIMIT_BACKEND": "disabled",
            }
        )


def test_redis_rate_limiter_requires_redis_url() -> None:
    """Require usable Redis configuration when the distributed backend is selected."""
    with pytest.raises(ValidationError):
        AppSettings(**{**BASE, "RATE_LIMIT_BACKEND": "redis"})


def test_redis_rate_limiter_accepts_valid_url() -> None:
    """Accept a valid Redis-backed rate-limit configuration."""
    settings = AppSettings(
        **{
            **BASE,
            "RATE_LIMIT_BACKEND": "redis",
            "REDIS_URL": "redis://localhost:6379/0",
        }
    )
    assert settings.redis_url_value == "redis://localhost:6379/0"


def test_trusted_proxy_requires_explicit_cidrs() -> None:
    """Prevent forwarded-address trust without an explicit proxy allowlist."""
    with pytest.raises(ValidationError):
        AppSettings(**{**BASE, "TRUSTED_PROXY_ENABLED": True})


def test_invalid_trusted_proxy_cidr_is_rejected() -> None:
    """Reject malformed trusted-proxy network definitions at startup."""
    with pytest.raises(ValidationError):
        AppSettings(
            **{
                **BASE,
                "TRUSTED_PROXY_ENABLED": True,
                "TRUSTED_PROXY_CIDRS": ["not-a-network"],
            }
        )


def test_default_registration_role_must_be_explicitly_allowlisted() -> None:
    """Prevent configuration from making a privileged role self-registerable."""
    with pytest.raises(
        ValidationError,
        match="DEFAULT_ROLE_CODE must be explicitly permitted",
    ):
        AppSettings(
            **{
                **BASE,
                "DEFAULT_ROLE_CODE": "platform_admin",
            }
        )


def test_self_registration_role_allowlist_accepts_configured_customer() -> None:
    settings = AppSettings(
        **{
            **BASE,
            "DEFAULT_ROLE_CODE": "customer",
            "SELF_REGISTRATION_ROLE_CODES": ["customer"],
        }
    )

    assert settings.SELF_REGISTRATION_ROLE_CODES == ["customer"]


def test_self_registration_role_allowlist_rejects_invalid_codes() -> None:
    with pytest.raises(
        ValidationError,
        match="contains invalid role codes",
    ):
        AppSettings(
            **{
                **BASE,
                "SELF_REGISTRATION_ROLE_CODES": ["Not Valid"],
            }
        )


def test_production_rejects_example_placeholder_secrets() -> None:
    """Prevent copied example credentials from satisfying production policy."""
    with pytest.raises(
        ValidationError,
        match="AUTH_PEPPER must be a non-placeholder",
    ):
        AppSettings(
            **{
                **BASE,
                **_rsa_settings(),
                "ENVIRONMENT": Environment.PRODUCTION,
                "POSTGRES_URL": (
                    "postgresql+asyncpg://identity:database-credential-7f2b@database/identity"
                ),
                "AUTH_PEPPER": ("replace-this-with-at-least-32-random-characters-0000000000000000"),
                "RATE_LIMIT_BACKEND": "redis",
                "REDIS_URL": ("rediss://identity:redis-credential-8c3d@redis.example.com:6379/0"),
                "DOCS_ENABLED": False,
                "LOG_JSON": True,
                "SECURE_HEADERS_ENABLED": True,
                "HSTS_ENABLED": True,
                "HOST_VALIDATION_ENABLED": True,
                "ALLOWED_HOSTS": ["identity.example.com"],
            }
        )
