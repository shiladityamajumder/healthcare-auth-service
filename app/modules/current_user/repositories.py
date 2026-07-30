"""File: app/modules/current_user/repositories.py

Purpose:
Implements user-by-identifier lookup and effective authorization-claim loading
for current-user workflows.

Dependency flow:
CurrentUserService inside SQLAlchemyUnitOfWork
-> CurrentUserRepository with the shared AsyncSession
-> user/authorization SQLAlchemy queries
-> PostgreSQL identity tables
-> ORM user or AuthorizationClaims

ORM mutations are committed only when the owning unit-of-work context exits.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.authorization.claims import AuthorizationClaims, load_authorization_claims
from app.models.identity import Users


class CurrentUserRepository:
    """Own user profile reads, updates, and authorization claim loading."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Users | None:
        """Load by ID, optionally locking the profile for a self-service update."""
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


__all__ = ["CurrentUserRepository"]
