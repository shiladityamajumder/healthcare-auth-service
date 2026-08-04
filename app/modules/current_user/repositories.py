"""File: app/modules/current_user/repositories.py

Purpose:
Implements identity/profile lookup, profile persistence, and effective
authorization-claim loading for current-user workflows.

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

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import FileAccessType, FileObjectStatus, MalwareScanStatus
from app.models.identity import UserProfiles, Users
from app.models.platform import IDENTITY_AVATAR_OWNER_TYPE, FileObjects


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

    async def get_active_profile(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> UserProfiles | None:
        """Load the non-deleted universal profile, optionally locking it."""
        statement = select(UserProfiles).where(
            UserProfiles.user_id == user_id,
            UserProfiles.is_deleted.is_(False),
        )
        if for_update:
            statement = statement.with_for_update()
        return (await self._session.scalars(statement)).first()

    def add_profile(self, profile: UserProfiles) -> None:
        """Stage a new universal profile in the current transaction."""
        self._session.add(profile)

    async def get_attachable_avatar_url(
        self,
        *,
        file_id: uuid.UUID,
        owner_user_id: uuid.UUID,
    ) -> str | None:
        """Resolve a client-safe avatar URL only when every file invariant holds."""
        statement = select(FileObjects.public_url).where(
            FileObjects.id == file_id,
            FileObjects.owner_type == IDENTITY_AVATAR_OWNER_TYPE,
            FileObjects.owner_id == owner_user_id,
            FileObjects.content_type.like("image/%"),
            FileObjects.access_type == FileAccessType.PUBLIC,
            FileObjects.status == FileObjectStatus.AVAILABLE,
            FileObjects.malware_scan_status == MalwareScanStatus.CLEAN,
            FileObjects.public_url.is_not(None),
            FileObjects.is_deleted.is_(False),
        )
        public_url = await self._session.scalar(statement)
        return str(public_url) if public_url is not None else None


__all__ = ["CurrentUserRepository"]
