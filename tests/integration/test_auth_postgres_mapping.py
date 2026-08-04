"""File: tests/integration/test_auth_postgres_mapping.py

Purpose:
Provides an opt-in integration check for every externally migrated table auth
requires in PostgreSQL.

Dependency flow:
Integration environment URL
-> PostgreSQLDatabase
-> bounded schema verification query
-> table-contract assertion
"""

from __future__ import annotations

import os

import pytest
from app.models.identity import UserProfiles
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.mark.asyncio
@pytest.mark.integration
async def test_required_auth_tables_are_available() -> None:
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
            platform_file_objects = await connection.scalar(
                text(
                    "SELECT EXISTS ("
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'platform' AND table_name = 'file_objects'"
                    ")"
                )
            )
            assert platform_file_objects is True
            # Exercise the real profile projection used by login/current-user
            # responses, including its filtered platform.file_objects subquery
            # and the row-lock form used by profile updates.
            await connection.execute(select(UserProfiles).limit(1).with_for_update())
    finally:
        await engine.dispose()
