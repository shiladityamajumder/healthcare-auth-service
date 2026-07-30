"""File: tests/conftest.py

Purpose:
Provides deterministic settings helpers shared by offline tests.

Dependency flow:
Test case
-> build_test_settings()
-> validated AppSettings overrides
-> isolated component/application construction
"""

from __future__ import annotations

import os
from typing import Any

# These values are set before importing app.main because that module exposes the
# default ASGI app at import time. No database connection occurs until lifespan.
os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault(
    "POSTGRES_URL",
    "postgresql+asyncpg://test:test@127.0.0.1:5432/pharmacy_identity_test",
)
os.environ.setdefault("DATABASE_STARTUP_CHECK", "false")
os.environ.setdefault("DATABASE_SCHEMA_CHECK", "false")
os.environ.setdefault("AUTH_PEPPER", "p" * 64)
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("JWT_SECRET", "s" * 80)
os.environ.setdefault("HOST_VALIDATION_ENABLED", "false")
os.environ.setdefault("DEEP_HEALTH_ENABLED", "false")
os.environ.setdefault("DOCS_ENABLED", "true")
os.environ.setdefault("OTP_DEV_EXPOSE_CODE", "false")

from app.core.config import AppSettings, Environment


def build_test_settings(**overrides: Any) -> AppSettings:
    values: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": Environment.TESTING,
        "DEBUG": False,
        "POSTGRES_URL": (
            "postgresql+asyncpg://test:test@127.0.0.1:5432/"
            "pharmacy_identity_test"
        ),
        "DATABASE_STARTUP_CHECK": False,
        "DATABASE_SCHEMA_CHECK": False,
        "AUTH_PEPPER": "p" * 64,
        "JWT_SECRET": "s" * 80,
        "HOST_VALIDATION_ENABLED": False,
        "DEEP_HEALTH_ENABLED": False,
        "DOCS_ENABLED": True,
        "OTP_DEV_EXPOSE_CODE": False,
    }
    values.update(overrides)
    return AppSettings(**values)
