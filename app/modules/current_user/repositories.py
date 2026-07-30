"""File: app/modules/current_user/repositories.py
SQLAlchemy persistence for current-user profile and authorization workflows."""

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
        """Load by id from persistence."""
        statement = select(Users).where(Users.id == user_id)
        if for_update:
            statement = statement.with_for_update()
        return await self._session.scalar(statement)

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
