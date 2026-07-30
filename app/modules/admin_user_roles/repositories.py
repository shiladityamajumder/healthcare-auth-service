"""File: app/modules/admin_user_roles/repositories.py
SQLAlchemy repository for user-role assignment administration."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import Roles, UserRoles, Users


class UserRoleRepository:
    """Persist and retrieve scoped role assignments."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def user_exists(self, user_id: uuid.UUID) -> bool:
        """Return whether a user exists."""
        return await self._session.scalar(
            select(Users.id).where(Users.id == user_id)
        ) is not None

    async def get_active_role(self, role_id: uuid.UUID) -> Roles | None:
        """Return a non-deleted role."""
        return await self._session.scalar(
            select(Roles).where(
                Roles.id == role_id,
                Roles.is_deleted.is_(False),
            )
        )

    async def list_for_user(
        self,
        user_id: uuid.UUID,
    ) -> list[tuple[UserRoles, Roles]]:
        """Return assignments and role metadata for one user."""
        statement = (
            select(UserRoles, Roles)
            .join(Roles, Roles.id == UserRoles.role_id)
            .where(UserRoles.user_id == user_id)
            .order_by(
                UserRoles.is_active.desc(),
                Roles.code.asc(),
                UserRoles.created_at.asc(),
            )
        )
        return list((await self._session.execute(statement)).all())

    async def get_assignment(
        self,
        *,
        user_id: uuid.UUID,
        assignment_id: uuid.UUID,
        for_update: bool = False,
    ) -> tuple[UserRoles, Roles] | None:
        """Return one user-owned assignment with role metadata."""
        statement = (
            select(UserRoles, Roles)
            .join(Roles, Roles.id == UserRoles.role_id)
            .where(
                UserRoles.id == assignment_id,
                UserRoles.user_id == user_id,
            )
        )
        if for_update:
            statement = statement.with_for_update(of=UserRoles)
        return (await self._session.execute(statement)).first()

    def add(self, assignment: UserRoles) -> None:
        """Stage a new assignment."""
        self._session.add(assignment)

    async def delete(self, assignment: UserRoles) -> None:
        """Delete an assignment record."""
        await self._session.delete(assignment)


__all__ = ["UserRoleRepository"]
