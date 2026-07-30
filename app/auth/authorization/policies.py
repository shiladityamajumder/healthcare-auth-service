"""File: app/auth/authorization/policies.py
Authentication workflow policies without transport or persistence coupling.

This module contains reusable business rules used by login, OTP verification,
password recovery, and password-management workflows.

The policies depend on small structural protocols rather than SQLAlchemy
models. Persistence models may satisfy these protocols, but the policy layer
does not import or depend directly on database mappings.

Role and permission authorization policies belong in
``app.auth.authorization`` and must not be added to this module.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from app.auth.security.passwords import PasswordManager
from app.auth.workflows.otp import (
    OTPFailure,
    OTPVerification,
)
from app.common.exceptions import (
    AccountDisabledError,
    AccountLockedError,
    OtpAlreadyUsedError,
    OtpAttemptsExceededError,
    OtpExpiredError,
    OtpInvalidError,
    ValidationError,
)
from app.core.config import AppSettings
from app.models.enums import (
    OTPChannel,
    UserStatus,
)
from app.utils.datetime_utils import utc_now


class AccountAccessSubject(Protocol):
    """Account attributes required by access policies."""

    status: UserStatus
    account_closed_at: datetime | None
    locked_until: datetime | None

    email: str | None
    email_verified_at: datetime | None

    phone_number: str | None
    phone_verified_at: datetime | None


class PasswordHistorySubject(Protocol):
    """User attributes required by password-history policies."""

    id: uuid.UUID
    password_hash: str | None


class PasswordHistoryRepositoryPort(Protocol):
    """Password-history persistence operations required by the policy."""

    async def recent_password_hashes(
        self,
        *,
        user_id: uuid.UUID,
        limit: int,
    ) -> list[str]:
        """Load recent password hashes in newest-first order.

        Args:
            user_id: User whose password history should be loaded.
            limit: Maximum number of historical hashes to return.

        Returns:
            Recent encoded password hashes.
        """

        ...


class AccountAccessPolicy:
    """Evaluate account state for authentication workflows."""

    @classmethod
    def ensure_login_allowed(
        cls,
        user: AccountAccessSubject,
        *,
        verified_channel: OTPChannel | str | None = None,
        allow_pending: bool = False,
    ) -> None:
        """Reject login when account state does not permit authentication.

        Args:
            user: Account state being evaluated.
            verified_channel: Channel used to authenticate the request.
            allow_pending: Whether pending-verification users may continue.

        Raises:
            AccountDisabledError: If the account is closed, suspended,
                unverified for the selected channel, or otherwise inactive.
            AccountLockedError: If the account is administratively or
                temporarily locked.
            ValueError: If ``verified_channel`` is unsupported.
        """
        now = utc_now()

        if (
            user.account_closed_at is not None
            or user.status == UserStatus.CLOSED
        ):
            raise AccountDisabledError(
                "The account has been closed."
            )

        if user.status == UserStatus.SUSPENDED:
            raise AccountDisabledError(
                "The account has been suspended."
            )

        if (
            user.status == UserStatus.LOCKED
            or cls._has_active_temporary_lock(
                user,
                now=now,
            )
        ):
            raise AccountLockedError()

        channel = cls._normalize_channel(
            verified_channel
        )

        if (
            channel == OTPChannel.EMAIL
            and (
                user.email is None
                or user.email_verified_at is None
            )
        ):
            raise AccountDisabledError(
                "Email verification is required before login."
            )

        if (
            channel == OTPChannel.SMS
            and (
                user.phone_number is None
                or user.phone_verified_at is None
            )
        ):
            raise AccountDisabledError(
                "Phone verification is required before login."
            )

        allowed_statuses = {
            UserStatus.ACTIVE,
        }

        if allow_pending:
            allowed_statuses.add(
                UserStatus.PENDING_VERIFICATION
            )

        if user.status not in allowed_statuses:
            raise AccountDisabledError(
                "The account is not permitted to log in."
            )

    @staticmethod
    def is_active(
        user: AccountAccessSubject,
    ) -> bool:
        """Return whether an account is currently active and unlocked.

        This method is appropriate for workflows that require an account to be
        fully active, such as login OTP delivery.

        Password-recovery workflows may intentionally use a different policy
        if locked users are allowed to recover access.

        Args:
            user: Account state being evaluated.

        Returns:
            ``True`` when the account is active, open, and not temporarily
            locked.
        """
        now = utc_now()

        return (
            user.status == UserStatus.ACTIVE
            and user.account_closed_at is None
            and not AccountAccessPolicy._has_active_temporary_lock(
                user,
                now=now,
            )
        )

    @staticmethod
    def _has_active_temporary_lock(
        user: AccountAccessSubject,
        *,
        now: datetime,
    ) -> bool:
        """Return whether an account has a non-expired timed lock."""
        return (
            user.locked_until is not None
            and user.locked_until > now
        )

    @staticmethod
    def _normalize_channel(
        value: OTPChannel | str | None,
    ) -> OTPChannel | None:
        """Normalize an optional OTP channel.

        Args:
            value: Enum member, enum value string, or ``None``.

        Returns:
            Normalized channel enum or ``None``.

        Raises:
            ValueError: If the supplied channel is unsupported.
        """
        if value is None:
            return None

        if isinstance(value, OTPChannel):
            return value

        normalized = value.strip().lower()

        if not normalized:
            return None

        try:
            return OTPChannel(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Unsupported OTP channel: {value}"
            ) from exc


class PasswordHistoryPolicy:
    """Prevent reuse of the current or recently used passwords."""

    def __init__(
        self,
        *,
        settings: AppSettings,
        passwords: PasswordManager,
    ) -> None:
        """Initialize the password-history policy.

        Args:
            settings: Validated password-history configuration.
            passwords: Shared password hashing and verification manager.
        """
        self._settings = settings
        self._passwords = passwords

    async def ensure_not_reused(
        self,
        *,
        users: PasswordHistoryRepositoryPort,
        user: PasswordHistorySubject,
        new_password: str,
    ) -> None:
        """Reject reuse of the current or recent passwords.

        The current password is always checked. Historical hashes are checked
        according to ``PASSWORD_HISTORY_COUNT``.

        Args:
            users: Password-history repository.
            user: User whose password is being changed.
            new_password: Candidate plaintext password.

        Raises:
            ValidationError: If the password matches the current password or
                a configured historical password.
        """
        history_limit = self._settings.PASSWORD_HISTORY_COUNT

        historical_hashes: list[str] = []

        if history_limit > 0:
            historical_hashes = (
                await users.recent_password_hashes(
                    user_id=user.id,
                    limit=history_limit,
                )
            )

        candidate_hashes = self._build_candidate_hashes(
            current_hash=user.password_hash,
            historical_hashes=historical_hashes,
        )

        for password_hash in candidate_hashes:
            reused = await self._passwords.verify(
                password_hash,
                new_password,
            )

            if reused:
                raise ValidationError(
                    "The new password was used recently."
                )

    @staticmethod
    def _build_candidate_hashes(
        *,
        current_hash: str | None,
        historical_hashes: list[str],
    ) -> tuple[str, ...]:
        """Build an ordered, deduplicated password-hash collection."""
        candidates: list[str] = []

        if current_hash and current_hash.strip():
            candidates.append(
                current_hash.strip()
            )

        for password_hash in historical_hashes:
            normalized_hash = password_hash.strip()

            if (
                normalized_hash
                and normalized_hash not in candidates
            ):
                candidates.append(
                    normalized_hash
                )

        return tuple(candidates)


class OtpVerificationPolicy:
    """Convert OTP verification outcomes into stable service exceptions."""

    @staticmethod
    def require_valid(
        result: OTPVerification,
    ) -> None:
        """Require a successful OTP verification result.

        Args:
            result: Internal OTP verification outcome.

        Raises:
            OtpExpiredError: If the OTP has expired.
            OtpAlreadyUsedError: If the OTP was already consumed.
            OtpAttemptsExceededError: If the challenge was blocked.
            OtpInvalidError: For invalid OTP values and unknown failures.
        """
        if result.valid:
            return

        match result.failure:
            case OTPFailure.EXPIRED:
                raise OtpExpiredError()

            case OTPFailure.CONSUMED:
                raise OtpAlreadyUsedError()

            case OTPFailure.BLOCKED:
                raise OtpAttemptsExceededError()

            case _:
                raise OtpInvalidError()


__all__ = [
    "AccountAccessPolicy",
    "AccountAccessSubject",
    "OtpVerificationPolicy",
    "PasswordHistoryPolicy",
    "PasswordHistoryRepositoryPort",
    "PasswordHistorySubject",
]
