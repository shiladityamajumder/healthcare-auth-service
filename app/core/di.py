"""File: app/core/di.py

Purpose:
Exposes settings, PostgreSQL sessions, and request-scoped units of work as
typed FastAPI dependency aliases.

Dependency flow:
FastAPI request
-> application state
-> PostgreSQLDatabase.session()
-> SQLAlchemyUnitOfWork
-> module service dependency
-> service-owned transaction; cleanup rolls back leftovers
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated, cast

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.exceptions import InfrastructureUnavailableError
from app.core.config import AppSettings
from app.db.postgres import PostgreSQLDatabase
from app.db.uow import SQLAlchemyUnitOfWork


def get_app_settings(request: Request) -> AppSettings:
    """Inject the process-wide validated settings into request providers."""
    return cast(AppSettings, request.app.state.settings)


def get_database(request: Request) -> PostgreSQLDatabase:
    """Inject the initialized database adapter or fail before route logic."""
    database = getattr(request.app.state, "database", None)
    if database is None:
        raise InfrastructureUnavailableError("PostgreSQL infrastructure has not completed startup.")
    return cast(PostgreSQLDatabase, database)


async def get_postgres_session(
    database: Annotated[PostgreSQLDatabase, Depends(get_database)],
) -> AsyncIterator[AsyncSession]:
    """Give one database session to all dependencies in the request graph."""
    async with database.session() as session:
        yield session


async def get_postgres_uow(
    session: Annotated[AsyncSession, Depends(get_postgres_session)],
) -> AsyncIterator[SQLAlchemyUnitOfWork]:
    """Inject a request-scoped transaction boundary and roll back leftovers."""
    uow = SQLAlchemyUnitOfWork(session)
    try:
        yield uow
    finally:
        if uow.is_active:
            await uow.rollback()


# These aliases let FastAPI cache one settings/database/session chain per request.
SettingsDep = Annotated[AppSettings, Depends(get_app_settings)]
DatabaseDep = Annotated[PostgreSQLDatabase, Depends(get_database)]
PostgresSessionDep = Annotated[AsyncSession, Depends(get_postgres_session)]

# Services enter this transaction boundary explicitly; the provider rolls back
# only an active transaction left behind during dependency cleanup.
PostgresUOWDep = Annotated[SQLAlchemyUnitOfWork, Depends(get_postgres_uow)]


__all__ = [
    "DatabaseDep",
    "PostgresSessionDep",
    "PostgresUOWDep",
    "SettingsDep",
    "get_app_settings",
    "get_database",
    "get_postgres_session",
    "get_postgres_uow",
]
