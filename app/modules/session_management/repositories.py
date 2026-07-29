"""SQLAlchemy persistence for user session inventory and revocation."""

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
        return await self._session.scalar(
            select(Sessions)
            .where(Sessions.id == session_id)
            .with_for_update()
        )


__all__ = ["SessionManagementRepository"]
