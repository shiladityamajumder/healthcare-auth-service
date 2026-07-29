"""SQLAlchemy persistence for registration workflows."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.authorization.claims import AuthorizationClaims, load_authorization_claims
from app.common.exceptions import InfrastructureUnavailableError
from app.models.identity import OtpChallenges, PasswordHistory, Roles, Sessions, UserRoles, Users


class RegistrationRepository:
    """Own every database operation required by registration use cases."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def email_exists(self, email: str) -> bool:
        """Return whether the normalized email is already registered."""
        return await self._session.scalar(
            select(Users.id).where(Users.email_normalized == email)
        ) is not None

    async def phone_exists(self, country_code: str, phone_number: str) -> bool:
        """Return whether the normalized phone number is already registered."""
        return await self._session.scalar(
            select(Users.id).where(
                Users.phone_country_code == country_code,
                Users.phone_number == phone_number,
            )
        ) is not None

    def add_user(self, user: Users) -> None:
        """Stage user in the current unit of work."""
        self._session.add(user)

    def add_password_history(self, *, user_id: uuid.UUID, password_hash: str) -> None:
        """Stage password history in the current unit of work."""
        self._session.add(PasswordHistory(user_id=user_id, password_hash=password_hash))

    async def assign_default_role(
        self,
        *,
        user_id: uuid.UUID,
        role_code: str,
        required: bool,
    ) -> bool:
        """Assign default role in persistence."""
        role = await self._session.scalar(
            select(Roles).where(Roles.code == role_code, Roles.is_deleted.is_(False))
        )
        if role is None:
            if required:
                raise InfrastructureUnavailableError(
                    f"Required default role '{role_code}' is missing."
                )
            return False
        self._session.add(
            UserRoles(
                user_id=user_id,
                role_id=role.id,
                scope_type=None,
                scope_id=None,
                is_active=True,
            )
        )
        return True

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
        return await self._session.scalar(
            select(OtpChallenges)
            .where(
                OtpChallenges.destination_hash == destination_hash,
                OtpChallenges.purpose == purpose,
            )
            .order_by(OtpChallenges.created_at.desc())
            .limit(1)
        )

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
        return int(result.rowcount or 0)

    async def get_for_update(self, challenge_id: uuid.UUID) -> OtpChallenges | None:
        """Load and lock an OTP challenge for verification."""
        return await self._session.scalar(
            select(OtpChallenges)
            .where(OtpChallenges.id == challenge_id)
            .with_for_update()
        )


__all__ = ["RegistrationRepository"]
