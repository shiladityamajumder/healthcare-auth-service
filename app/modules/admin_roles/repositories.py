"""File: app/modules/admin_roles/repositories.py

Purpose:
Implements active-role lookup, uniqueness checks, and ORM staging for role
administration.

Dependency flow:
AdminRolesService inside SQLAlchemyUnitOfWork
-> RoleRepository with the shared AsyncSession
-> active/soft-delete-aware SQLAlchemy statements
-> PostgreSQL roles table
-> ORM entities returned or staged

``add()`` stages ORM state only; transaction completion belongs to the unit of
work.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import Roles


class RoleRepository:
    """Persist and retrieve active role records."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_active(self) -> list[Roles]:
        """Return all non-deleted roles in deterministic order."""
        statement = (
            select(Roles)
            .where(Roles.is_deleted.is_(False))
            .order_by(Roles.is_system.desc(), Roles.code.asc())
        )
        return list((await self._session.scalars(statement)).all())

    async def get_active(
        self,
        role_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Roles | None:
        """Return one active role, optionally locked."""
        statement = select(Roles).where(
            Roles.id == role_id,
            Roles.is_deleted.is_(False),
        )
        if for_update:
            statement = statement.with_for_update()
        return (await self._session.scalars(statement)).first()

    async def code_exists(
        self,
        code: str,
        *,
        exclude_role_id: uuid.UUID | None = None,
    ) -> bool:
        """Check active role-code uniqueness."""
        statement = select(Roles.id).where(
            Roles.code == code,
            Roles.is_deleted.is_(False),
        )
        if exclude_role_id is not None:
            statement = statement.where(Roles.id != exclude_role_id)
        return await self._session.scalar(statement) is not None

    def add(self, role: Roles) -> None:
        """Stage a new role."""
        self._session.add(role)


__all__ = ["RoleRepository"]
