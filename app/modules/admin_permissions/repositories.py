"""File: app/modules/admin_permissions/repositories.py

Purpose:
Implements active permission/role lookups, uniqueness checks, and atomic
role-permission mapping replacement over SQLAlchemy.

Dependency flow:
AdminPermissionsService inside SQLAlchemyUnitOfWork
-> PermissionRepository with the shared AsyncSession
-> active/soft-delete-aware statements
-> PostgreSQL permission and mapping tables
-> ORM entities or staged mapping changes

Deletes and additions remain uncommitted until the owning unit of work exits.
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import Permissions, RolePermissions, Roles


class PermissionRepository:
    """Persist permission masters and their role-policy mappings."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_active(self) -> list[Permissions]:
        """Return active permissions ordered by resource, action, and code."""
        statement = (
            select(Permissions)
            .where(Permissions.is_deleted.is_(False))
            .order_by(
                Permissions.resource.asc(),
                Permissions.action.asc(),
                Permissions.code.asc(),
            )
        )
        return list((await self._session.scalars(statement)).all())

    async def get_active(
        self,
        permission_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Permissions | None:
        """Return an active permission, optionally locking it for mutation."""
        statement = select(Permissions).where(
            Permissions.id == permission_id,
            Permissions.is_deleted.is_(False),
        )
        if for_update:
            statement = statement.with_for_update()
        return (await self._session.scalars(statement)).first()

    async def code_exists(
        self,
        code: str,
        *,
        exclude_permission_id: uuid.UUID | None = None,
    ) -> bool:
        """Return whether another active permission uses the supplied code."""
        statement = select(Permissions.id).where(
            Permissions.code == code,
            Permissions.is_deleted.is_(False),
        )
        if exclude_permission_id is not None:
            statement = statement.where(Permissions.id != exclude_permission_id)
        return (await self._session.scalars(statement)).first() is not None

    def add(self, permission: Permissions) -> None:
        """Stage a permission master inside the current unit of work."""
        self._session.add(permission)

    async def get_role(
        self,
        role_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Roles | None:
        """Return an active role, optionally locked."""
        statement = select(Roles).where(
            Roles.id == role_id,
            Roles.is_deleted.is_(False),
        )
        if for_update:
            statement = statement.with_for_update()
        return (await self._session.scalars(statement)).first()

    async def list_for_role(self, role_id: uuid.UUID) -> list[Permissions]:
        """Return active permissions currently assigned to a role."""
        statement = (
            select(Permissions)
            .join(
                RolePermissions,
                RolePermissions.permission_id == Permissions.id,
            )
            .where(
                RolePermissions.role_id == role_id,
                Permissions.is_deleted.is_(False),
            )
            .order_by(Permissions.code.asc())
        )
        return list((await self._session.scalars(statement)).all())

    async def get_active_by_ids(
        self,
        permission_ids: list[uuid.UUID],
    ) -> list[Permissions]:
        """Return all active permissions matching the supplied IDs."""
        if not permission_ids:
            return []
        statement = select(Permissions).where(
            Permissions.id.in_(permission_ids),
            Permissions.is_deleted.is_(False),
        )
        return list((await self._session.scalars(statement)).all())

    async def replace_role_permissions(
        self,
        *,
        role_id: uuid.UUID,
        permission_ids: list[uuid.UUID],
        actor_user_id: uuid.UUID,
    ) -> None:
        """Replace mappings inside the caller's transaction."""
        await self._session.execute(
            delete(RolePermissions).where(RolePermissions.role_id == role_id)
        )
        self._session.add_all(
            [
                RolePermissions(
                    role_id=role_id,
                    permission_id=permission_id,
                    created_by=actor_user_id,
                    updated_by=actor_user_id,
                )
                for permission_id in permission_ids
            ]
        )


__all__ = ["PermissionRepository"]
