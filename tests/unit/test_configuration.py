from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import AppSettings, Environment


BASE = {
    "_env_file": None,
    "POSTGRES_URL": "postgresql+asyncpg://user:password@localhost/database",
    "AUTH_PEPPER": "p" * 64,
    "JWT_SECRET": "s" * 80,
}


def test_single_configuration_accepts_postgresql_development() -> None:
    settings = AppSettings(**BASE)
    assert settings.postgres_url_value.startswith("postgresql+asyncpg://")
    assert settings.auth_pepper_value == "p" * 64


def test_non_async_postgresql_url_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AppSettings(**{**BASE, "POSTGRES_URL": "postgresql://user:pass@localhost/db"})


def test_production_rejects_symmetric_jwt() -> None:
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


def test_redis_rate_limiter_requires_redis_url() -> None:
    with pytest.raises(ValidationError):
        AppSettings(**{**BASE, "RATE_LIMIT_BACKEND": "redis"})


def test_redis_rate_limiter_accepts_valid_url() -> None:
    settings = AppSettings(
        **{
            **BASE,
            "RATE_LIMIT_BACKEND": "redis",
            "REDIS_URL": "redis://localhost:6379/0",
        }
    )
    assert settings.redis_url_value == "redis://localhost:6379/0"


def test_trusted_proxy_requires_explicit_cidrs() -> None:
    with pytest.raises(ValidationError):
        AppSettings(**{**BASE, "TRUSTED_PROXY_ENABLED": True})


def test_invalid_trusted_proxy_cidr_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AppSettings(
            **{
                **BASE,
                "TRUSTED_PROXY_ENABLED": True,
                "TRUSTED_PROXY_CIDRS": ["not-a-network"],
            }
        )
