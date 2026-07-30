"""File: app/modules/email_verification/repositories.py
SQLAlchemy persistence for email-verification workflows."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.authorization.claims import AuthorizationClaims, load_authorization_claims
from app.models.identity import OtpChallenges, Sessions, Users


class EmailVerificationRepository:
    """Own user, OTP, authorization, and session operations for verification."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_user_by_email(
        self,
        email: str,
        *,
        for_update: bool = False,
    ) -> Users | None:
        """Load user by email from persistence."""
        statement = select(Users).where(Users.email_normalized == email)
        if for_update:
            statement = statement.with_for_update()
        return (await self._session.scalars(statement)).first()

    def mark_email_verified(self, user: Users, *, verified_at: datetime) -> None:
        """Mark email verified in the current unit of work."""
        user.email_verified_at = user.email_verified_at or verified_at

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

    def add_session(self, session_record: Sessions) -> None:
        """Stage a newly issued session for persistence."""
        self._session.add(session_record)

    def add(self, challenge: OtpChallenges) -> None:
        """Stage a new OTP challenge in the current unit of work."""
        self._session.add(challenge)

    async def acquire_issue_lock(self, *, destination_hash: str, purpose: str) -> None:
        """Acquire a transaction-scoped lock for OTP issuance."""
        await self._session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
            {"lock_key": f"{destination_hash}:{purpose}"},
        )

    async def count_recent_issues(
        self,
        *,
        destination_hash: str,
        purpose: str,
        since: datetime,
    ) -> int:
        """Count recent issues in persistence."""
        statement = select(func.count(OtpChallenges.id)).where(
            OtpChallenges.destination_hash == destination_hash,
            OtpChallenges.purpose == purpose,
            OtpChallenges.created_at >= since,
        )
        return int(await self._session.scalar(statement) or 0)

    async def latest_for_destination(
        self,
        *,
        destination_hash: str,
        purpose: str,
    ) -> OtpChallenges | None:
        """Load the latest for destination from persistence."""
        statement = (
            select(OtpChallenges)
            .where(
                OtpChallenges.destination_hash == destination_hash,
                OtpChallenges.purpose == purpose,
            )
            .order_by(OtpChallenges.created_at.desc())
            .limit(1)
        )
        return (await self._session.scalars(statement)).first()

    async def invalidate_active(
        self,
        *,
        destination_hash: str,
        purpose: str,
        consumed_at: datetime,
    ) -> int:
        """Invalidate active in persistence."""
        result = await self._session.execute(
            update(OtpChallenges)
            .where(
                OtpChallenges.destination_hash == destination_hash,
                OtpChallenges.purpose == purpose,
                OtpChallenges.consumed_at.is_(None),
                OtpChallenges.blocked_at.is_(None),
            )
            .values(consumed_at=consumed_at)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    async def get_for_update(self, challenge_id: uuid.UUID) -> OtpChallenges | None:
        """Load and lock an OTP challenge for verification."""
        statement = select(OtpChallenges).where(OtpChallenges.id == challenge_id).with_for_update()
        return (await self._session.scalars(statement)).first()


__all__ = ["EmailVerificationRepository"]
