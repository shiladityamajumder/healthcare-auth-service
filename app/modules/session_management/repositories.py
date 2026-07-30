"""File: app/modules/session_management/repositories.py

Purpose:
Implements active session inventory and row-locked session lookup for safe
user-owned revocation.

Dependency flow:
SessionManagementService inside SQLAlchemyUnitOfWork
-> SessionManagementRepository with the shared AsyncSession
-> user-owned active-session filters or FOR UPDATE lookup
-> PostgreSQL sessions table
-> ORM sessions returned to the service

The service verifies ownership after the locked lookup before staging
revocation; commit remains with the unit of work.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import Sessions


class SessionManagementRepository:
    """Own active-session reads and user-scoped revocation writes."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_active(
        self,
        *,
        user_id: uuid.UUID,
        now: datetime,
    ) -> list[Sessions]:
        """List active visible to the current workflow."""
        statement = (
            select(Sessions)
            .where(
                Sessions.user_id == user_id,
                Sessions.revoked_at.is_(None),
                Sessions.expires_at > now,
            )
            .order_by(
                Sessions.last_seen_at.desc().nullslast(),
                Sessions.created_at.desc(),
            )
        )
        return list((await self._session.scalars(statement)).all())

    async def get_for_update(self, session_id: uuid.UUID) -> Sessions | None:
        """Load and lock one user-owned session for revocation."""
        statement = select(Sessions).where(Sessions.id == session_id).with_for_update()
        return (await self._session.scalars(statement)).first()


__all__ = ["SessionManagementRepository"]
