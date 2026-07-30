"""File: app/modules/token_management/repositories.py

Purpose:
Implements row-locked session lookup, user/authorization loading, token-family
revocation, and user-wide session revocation.

Dependency flow:
TokenManagementService inside SQLAlchemyUnitOfWork
-> TokenRepository with the shared AsyncSession
-> session/user/family-filtered SQLAlchemy statements
-> PostgreSQL identity tables
-> locked ORM state or mutation counts

Revocation updates are staged in the active transaction and committed only by
the unit of work.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.authorization.claims import AuthorizationClaims, load_authorization_claims
from app.models.identity import Sessions, Users


class TokenRepository:
    """Own persistence operations used by token rotation and logout."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_session(
        self,
        session_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Sessions | None:
        """Load a session, optionally locking it for token rotation/revocation."""
        statement = select(Sessions).where(Sessions.id == session_id)
        if for_update:
            statement = statement.with_for_update()
        return (await self._session.scalars(statement)).first()

    async def get_user(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Users | None:
        """Load a user, optionally locking account state during refresh."""
        statement = select(Users).where(Users.id == user_id)
        if for_update:
            statement = statement.with_for_update()
        return (await self._session.scalars(statement)).first()

    async def authorization_claims(
        self,
        *,
        user_id: uuid.UUID,
        now: datetime,
    ) -> AuthorizationClaims:
        """Load effective roles and permissions for a user."""
        return await load_authorization_claims(
            self._session,
            user_id=user_id,
            now=now,
        )

    async def revoke_family(
        self,
        *,
        family_id: uuid.UUID,
        revoked_at: datetime,
        reason: str,
    ) -> int:
        """Revoke family in persistence."""
        result = await self._session.execute(
            update(Sessions)
            .where(
                Sessions.token_family_id == family_id,
                Sessions.revoked_at.is_(None),
            )
            .values(revoked_at=revoked_at, revoke_reason=reason)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def revoke_user_sessions(
        self,
        *,
        user_id: uuid.UUID,
        revoked_at: datetime,
        reason: str,
        except_session_id: uuid.UUID | None = None,
    ) -> int:
        """Revoke user sessions in persistence."""
        statement = update(Sessions).where(
            Sessions.user_id == user_id,
            Sessions.revoked_at.is_(None),
        )
        if except_session_id is not None:
            statement = statement.where(Sessions.id != except_session_id)
        result = await self._session.execute(
            statement.values(revoked_at=revoked_at, revoke_reason=reason)
        )
        return int(getattr(result, "rowcount", 0) or 0)


__all__ = ["TokenRepository"]
