"""SQLAlchemy repositories for administrative user workflows."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.authorization import AuthorizationClaims, load_authorization_claims
from app.core.pagination import PaginationParams, PaginationResult, paginate_scalars
from app.models.enums import UserStatus
from app.models.identity import Sessions, Users


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
        return await self._session.scalar(statement)

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
            filters.append(
                or_(
                    Users.email_normalized.ilike(pattern),
                    Users.phone_number.ilike(pattern),
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
        return int(result.rowcount or 0)


__all__ = ["AdminUserRepository"]
