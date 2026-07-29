"""Shared SQL authorization claim loading used by the auth kernel and modules."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import Permissions, RolePermissions, Roles, UserRoles


@dataclass(frozen=True, slots=True)
class AuthorizationClaims:
    """Effective global role and permission codes."""

    roles: list[str]
    permissions: list[str]


async def load_authorization_claims(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    now: datetime,
) -> AuthorizationClaims:
    """Load active, unexpired, global RBAC assignments for a user."""
    role_statement = (
        select(Roles.code)
        .join(UserRoles, UserRoles.role_id == Roles.id)
        .where(
            UserRoles.user_id == user_id,
            UserRoles.is_active.is_(True),
            UserRoles.scope_type.is_(None),
            UserRoles.scope_id.is_(None),
            or_(UserRoles.valid_from.is_(None), UserRoles.valid_from <= now),
            or_(UserRoles.valid_until.is_(None), UserRoles.valid_until > now),
            Roles.is_deleted.is_(False),
        )
        .distinct()
        .order_by(Roles.code.asc())
    )
    permission_statement = (
        select(Permissions.code)
        .join(RolePermissions, RolePermissions.permission_id == Permissions.id)
        .join(Roles, Roles.id == RolePermissions.role_id)
        .join(UserRoles, UserRoles.role_id == Roles.id)
        .where(
            UserRoles.user_id == user_id,
            UserRoles.is_active.is_(True),
            UserRoles.scope_type.is_(None),
            UserRoles.scope_id.is_(None),
            or_(UserRoles.valid_from.is_(None), UserRoles.valid_from <= now),
            or_(UserRoles.valid_until.is_(None), UserRoles.valid_until > now),
            Roles.is_deleted.is_(False),
            Permissions.is_deleted.is_(False),
        )
        .distinct()
        .order_by(Permissions.code.asc())
    )
    roles = list((await session.scalars(role_statement)).all())
    permissions = list((await session.scalars(permission_statement)).all())
    return AuthorizationClaims(roles=roles, permissions=permissions)


__all__ = ["AuthorizationClaims", "load_authorization_claims"]
