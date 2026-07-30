"""File: app/modules/admin_users/repositories.py

Purpose:
Implements SQLAlchemy identity/profile reads, pagination, authorization-claim
loading, and session revocation for administrative user workflows.

Dependency flow:
AdminUsersService inside SQLAlchemyUnitOfWork
-> AdminUserRepository with the shared AsyncSession
-> filtered SQLAlchemy statements
-> PostgreSQL identity tables
-> ORM entities/counts returned to the service

Repository methods flush no transaction here; commit and rollback remain with
the request-scoped unit of work.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.authorization.claims import AuthorizationClaims, load_authorization_claims
from app.core.pagination import PaginationParams, PaginationResult, paginate_scalars
from app.models.enums import UserStatus
from app.models.identity import Sessions, UserProfiles, Users


class AdminUserRepository:
    """Read and lock users for administrative workflows."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Users | None:
        """Return a user by ID, optionally acquiring a row lock."""
        statement = select(Users).where(Users.id == user_id)
        if for_update:
            statement = statement.with_for_update()
        return (await self._session.scalars(statement)).first()

    async def list(
        self,
        *,
        pagination: PaginationParams,
        search: str | None,
        status: UserStatus | None,
    ) -> PaginationResult[Users]:
        """Return a deterministic filtered user page."""
        filters = []
        if search:
            pattern = f"%{search.strip()}%"
            profile_match = (
                select(UserProfiles.id)
                .where(
                    UserProfiles.user_id == Users.id,
                    UserProfiles.is_deleted.is_(False),
                    or_(
                        UserProfiles.first_name.ilike(pattern),
                        UserProfiles.last_name.ilike(pattern),
                        UserProfiles.preferred_name.ilike(pattern),
                        func.concat_ws(
                            " ",
                            UserProfiles.first_name,
                            UserProfiles.last_name,
                        ).ilike(pattern),
                    ),
                )
                .exists()
            )
            filters.append(
                or_(
                    Users.email_normalized.ilike(pattern),
                    Users.phone_number.ilike(pattern),
                    profile_match,
                )
            )
        if status is not None:
            filters.append(Users.status == status)

        data_statement = select(Users).where(*filters).order_by(Users.created_at.desc(), Users.id)
        count_statement = select(func.count(Users.id)).where(*filters)
        return await paginate_scalars(
            session=self._session,
            data_statement=data_statement,
            count_statement=count_statement,
            params=pagination,
        )

    async def active_profiles_by_user_ids(
        self,
        user_ids: Sequence[uuid.UUID],
    ) -> dict[uuid.UUID, UserProfiles]:
        """Load active profiles for a user page in one database round trip."""
        if not user_ids:
            return {}
        profiles = await self._session.scalars(
            select(UserProfiles).where(
                UserProfiles.user_id.in_(user_ids),
                UserProfiles.is_deleted.is_(False),
            )
        )
        return {profile.user_id: profile for profile in profiles}

    async def get_active_profile(self, user_id: uuid.UUID) -> UserProfiles | None:
        """Load the non-deleted universal profile for one user."""
        statement = select(UserProfiles).where(
            UserProfiles.user_id == user_id,
            UserProfiles.is_deleted.is_(False),
        )
        return (await self._session.scalars(statement)).first()

    async def authorization_claims(
        self,
        *,
        user_id: uuid.UUID,
        now: datetime,
    ) -> AuthorizationClaims:
        """Return active global role and permission codes."""
        return await load_authorization_claims(
            self._session,
            user_id=user_id,
            now=now,
        )

    async def revoke_user_sessions(
        self,
        *,
        user_id: uuid.UUID,
        revoked_at: datetime,
        reason: str,
    ) -> int:
        """Revoke every active session for an administratively managed user."""
        result = await self._session.execute(
            update(Sessions)
            .where(
                Sessions.user_id == user_id,
                Sessions.revoked_at.is_(None),
            )
            .values(revoked_at=revoked_at, revoke_reason=reason)
        )
        return int(getattr(result, "rowcount", 0) or 0)


__all__ = ["AdminUserRepository"]
