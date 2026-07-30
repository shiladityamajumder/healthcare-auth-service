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

import pytest
from app.core.config import AppSettings, Environment
from pydantic import ValidationError

BASE = {
    "_env_file": None,
    "POSTGRES_URL": "postgresql+asyncpg://user:password@localhost/database",
    "AUTH_PEPPER": "p" * 64,
    "JWT_SECRET": "s" * 80,
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
