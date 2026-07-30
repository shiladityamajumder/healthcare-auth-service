"""File: tests/integration/test_auth_postgres_mapping.py

Purpose:
Provides an opt-in integration check for required externally migrated identity
tables in PostgreSQL.

Dependency flow:
Integration environment URL
-> PostgreSQLDatabase
-> bounded schema verification query
-> table-contract assertion
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.mark.asyncio
@pytest.mark.integration
async def test_required_identity_tables_are_available() -> None:
    if os.getenv("RUN_POSTGRES_INTEGRATION", "false").casefold() != "true":
        pytest.skip("Set RUN_POSTGRES_INTEGRATION=true for database tests")

    url = os.getenv("POSTGRES_URL")
    if not url:
        pytest.skip("POSTGRES_URL is not configured")

    required = {
        "users",
        "user_profiles",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "sessions",
        "otp_challenges",
        "mfa_factors",
        "trusted_devices",
        "login_attempts",
        "password_history",
        "api_clients",
        "api_client_secrets",
    }

    engine = create_async_engine(url)
    try:
        async with engine.connect() as connection:
            rows = await connection.scalars(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'identity'"
                )
            )
            available = set(rows.all())
            assert required.issubset(available)
    finally:
        await engine.dispose()
