"""File: app/db/postgres.py

Purpose:
Owns the process-wide PostgreSQL engine/session factory and yields isolated
request-scoped AsyncSession instances.

Dependency flow:
Validated database settings
-> process-wide async engine/sessionmaker
-> DatabaseDep session context
-> SQLAlchemyUnitOfWork and repositories
-> session close; engine disposal at shutdown
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import AppSettings
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class DatabaseHealth:
    """Sanitized PostgreSQL connectivity and schema health result."""

    healthy: bool
    schema_ready: bool
    duration_ms: float


class PostgreSQLDatabase:
    """Own one asynchronous engine and session factory per process."""

    def __init__(self, settings: AppSettings) -> None:
        self._engine: AsyncEngine = create_async_engine(
            settings.postgres_url_value,
            pool_size=settings.SQL_POOL_SIZE,
            max_overflow=settings.SQL_MAX_OVERFLOW,
            pool_timeout=settings.SQL_POOL_TIMEOUT_SECONDS,
            pool_recycle=settings.SQL_POOL_RECYCLE_SECONDS,
            pool_pre_ping=settings.SQL_POOL_PRE_PING,
            pool_use_lifo=True,
            pool_reset_on_return="rollback",
            connect_args={
                "timeout": settings.POSTGRES_CONNECT_TIMEOUT_SECONDS,
                "command_timeout": settings.POSTGRES_COMMAND_TIMEOUT_SECONDS,
                "server_settings": {
                    "application_name": settings.PROJECT_NAME,
                    "timezone": "UTC",
                },
            },
            echo=settings.SQL_ECHO,
            hide_parameters=True,
        )
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            autoflush=False,
            expire_on_commit=False,
        )

    @property
    def engine(self) -> AsyncEngine:
        """Expose the engine only for infrastructure tooling and tests."""

        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession]:
        """Yield an isolated session and always clean leaked transactions."""

        session = self._session_factory()
        try:
            yield session
        finally:
            try:
                if session.in_transaction():
                    await session.rollback()
            finally:
                await session.close()

    async def ping(self) -> None:
        """Execute a lightweight database connectivity query."""

        async with self._engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

    async def verify_required_schemas(self) -> bool:
        """Return whether every externally managed table required by auth exists."""

        statement = text(
            "SELECT "
            "to_regclass('identity.users') IS NOT NULL AND "
            "to_regclass('identity.user_profiles') IS NOT NULL AND "
            "to_regclass('identity.roles') IS NOT NULL AND "
            "to_regclass('identity.permissions') IS NOT NULL AND "
            "to_regclass('identity.user_roles') IS NOT NULL AND "
            "to_regclass('identity.role_permissions') IS NOT NULL AND "
            "to_regclass('identity.sessions') IS NOT NULL AND "
            "to_regclass('identity.otp_challenges') IS NOT NULL AND "
            "to_regclass('identity.mfa_factors') IS NOT NULL AND "
            "to_regclass('identity.trusted_devices') IS NOT NULL AND "
            "to_regclass('identity.login_attempts') IS NOT NULL AND "
            "to_regclass('identity.password_history') IS NOT NULL AND "
            "to_regclass('identity.api_clients') IS NOT NULL AND "
            "to_regclass('identity.api_client_secrets') IS NOT NULL AND "
            "to_regclass('platform.file_objects') IS NOT NULL"
        )
        async with self._engine.connect() as connection:
            return bool(await connection.scalar(statement))

    async def check(
        self,
        *,
        timeout_seconds: float,
        verify_schema: bool = True,
    ) -> DatabaseHealth:
        """Return bounded connectivity and externally migrated schema health."""

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        started = time.perf_counter()
        healthy = True
        schema_ready = not verify_schema
        try:
            async with asyncio.timeout(timeout_seconds):
                await self.ping()
                if verify_schema:
                    schema_ready = await self.verify_required_schemas()
        except Exception:
            healthy = False
            schema_ready = False
            logger.warning("PostgreSQL health check failed", exc_info=True)

        return DatabaseHealth(
            healthy=healthy,
            schema_ready=schema_ready,
            duration_ms=round((time.perf_counter() - started) * 1_000, 2),
        )

    async def close(self) -> None:
        """Dispose the engine and every pooled connection."""

        await self._engine.dispose()
        logger.info("PostgreSQL engine disposed")


__all__ = ["DatabaseHealth", "PostgreSQLDatabase"]
