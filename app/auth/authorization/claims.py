"""File: app/auth/authorization/claims.py

Purpose:
Loads effective active global role and permission claims from PostgreSQL.

Dependency flow:
Authenticated user identifier and AsyncSession
-> active assignment/role/permission queries
-> AuthorizationClaims
-> principal refresh or service response

This module contains the SQL-backed claim loader used by authentication module
services and request authentication dependencies.

It does not make authorization decisions. Authorization policies consume the
returned claims without accessing the database directly.

Only global role assignments are loaded here. Scoped authorization should use
a separate explicit loader so global and tenant, organization, warehouse, or
resource-level assignments are never mixed accidentally.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import (
    Permissions,
    RolePermissions,
    Roles,
    UserRoles,
)
from app.utils.datetime_utils import to_utc


@dataclass(frozen=True, slots=True)
class AuthorizationClaims:
    """Effective global authorization claims for one user.

    Roles and permissions are stored as sorted tuples. Tuples preserve stable
    ordering while preventing callers from mutating the loaded claim set.

    Attributes:
        roles: Effective global role codes.
        permissions: Effective permission codes granted through those roles.
    """

    roles: tuple[str, ...]
    permissions: tuple[str, ...]

    @classmethod
    def empty(cls) -> AuthorizationClaims:
        """Return an empty authorization claim set."""
        return cls(
            roles=(),
            permissions=(),
        )

    def has_role(self, role_code: str) -> bool:
        """Return whether the claim set contains a role.

        Args:
            role_code: Exact normalized role code.

        Returns:
            ``True`` when the role is present.
        """
        normalized_role = role_code.strip()

        if not normalized_role:
            return False

        return normalized_role in self.roles

    def has_permission(self, permission_code: str) -> bool:
        """Return whether the claim set contains a permission.

        Args:
            permission_code: Exact normalized permission code.

        Returns:
            ``True`` when the permission is present.
        """
        normalized_permission = permission_code.strip()

        if not normalized_permission:
            return False

        return normalized_permission in self.permissions


async def load_authorization_claims(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    now: datetime,
) -> AuthorizationClaims:
    """Load active, effective, global RBAC claims for a user.

    A role assignment is considered effective when:

    * It belongs to the requested user.
    * It is marked active.
    * It is a global assignment without a scope.
    * Its validity window includes ``now``.
    * The corresponding role has not been soft-deleted.

    Permission claims are loaded only through those effective roles and exclude
    soft-deleted permissions.

    Args:
        session: Request-scoped SQLAlchemy asynchronous session.
        user_id: User whose effective authorization claims are required.
        now: Timezone-aware timestamp used to evaluate validity windows.

    Returns:
        Sorted immutable role and permission claims.

    Raises:
        ValueError: If ``now`` is timezone-naive.
        SQLAlchemyError: Propagates database execution failures to the owning
            service or request dependency.
    """
    effective_at = to_utc(now)

    effective_role_ids = (
        select(UserRoles.role_id)
        .where(
            UserRoles.user_id == user_id,
            UserRoles.is_active.is_(True),
            UserRoles.scope_type.is_(None),
            UserRoles.scope_id.is_(None),
            or_(
                UserRoles.valid_from.is_(None),
                UserRoles.valid_from <= effective_at,
            ),
            or_(
                UserRoles.valid_until.is_(None),
                UserRoles.valid_until > effective_at,
            ),
        )
        .distinct()
        .cte("effective_global_role_ids")
    )

    role_statement = (
        select(Roles.code)
        .join(
            effective_role_ids,
            effective_role_ids.c.role_id == Roles.id,
        )
        .where(
            Roles.is_deleted.is_(False),
        )
        .distinct()
        .order_by(
            Roles.code.asc(),
        )
    )

    permission_statement = (
        select(Permissions.code)
        .join(
            RolePermissions,
            RolePermissions.permission_id == Permissions.id,
        )
        .join(
            effective_role_ids,
            effective_role_ids.c.role_id == RolePermissions.role_id,
        )
        .join(
            Roles,
            Roles.id == RolePermissions.role_id,
        )
        .where(
            Roles.is_deleted.is_(False),
            Permissions.is_deleted.is_(False),
        )
        .distinct()
        .order_by(
            Permissions.code.asc(),
        )
    )

    role_result = await session.scalars(role_statement)
    permission_result = await session.scalars(permission_statement)

    return AuthorizationClaims(
        roles=tuple(role_result.all()),
        permissions=tuple(permission_result.all()),
    )


__all__ = [
    "AuthorizationClaims",
    "load_authorization_claims",
]
