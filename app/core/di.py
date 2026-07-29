"""FastAPI dependency providers for the PostgreSQL transaction boundary."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.exceptions import InfrastructureUnavailableError
from app.core.config import AppSettings
from app.db.postgres import PostgreSQLDatabase
from app.db.uow import SQLAlchemyUnitOfWork


def get_app_settings(request: Request) -> AppSettings:
    return request.app.state.settings


def get_database(request: Request) -> PostgreSQLDatabase:
    database = getattr(request.app.state, "database", None)
    if database is None:
        raise InfrastructureUnavailableError(
            "PostgreSQL infrastructure has not completed startup."
        )
    return database


async def get_postgres_session(
    database: Annotated[PostgreSQLDatabase, Depends(get_database)],
) -> AsyncIterator[AsyncSession]:
    async with database.session() as session:
        yield session


async def get_postgres_uow(
    session: Annotated[AsyncSession, Depends(get_postgres_session)],
) -> AsyncIterator[SQLAlchemyUnitOfWork]:
    uow = SQLAlchemyUnitOfWork(session)
    try:
        yield uow
    finally:
        if uow.is_active:
            await uow.rollback()


SettingsDep = Annotated[AppSettings, Depends(get_app_settings)]
DatabaseDep = Annotated[PostgreSQLDatabase, Depends(get_database)]
PostgresSessionDep = Annotated[AsyncSession, Depends(get_postgres_session)]
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
