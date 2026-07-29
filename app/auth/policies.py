"""Shared authentication policies without transport or persistence coupling."""

from __future__ import annotations

import uuid
from typing import Protocol

from app.auth.otp import OTPFailure, OTPVerification
from app.auth.security.passwords import PasswordManager
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
from app.models.enums import OTPChannel, UserStatus
from app.models.identity import Users
from app.utils.datetime_utils import utc_now


class PasswordHistoryRepositoryPort(Protocol):
    """Password-history reads required by the shared policy."""

    async def recent_password_hashes(
        self,
        *,
        user_id: uuid.UUID,
        limit: int,
    ) -> list[str]:
        """Load recent password hashes for reuse prevention."""
        ...


class AccountAccessPolicy:
    """Central account-state checks used by login and recovery workflows."""

    @staticmethod
    def ensure_login_allowed(
        user: Users,
        *,
        verified_channel: str | None = None,
        allow_pending: bool = False,
    ) -> None:
        """Reject login when the account state does not permit authentication."""
        now = utc_now()
        if user.account_closed_at is not None or user.status == UserStatus.CLOSED:
            raise AccountDisabledError()
        if user.status in {UserStatus.SUSPENDED, UserStatus.LOCKED}:
            raise AccountDisabledError()
        if user.locked_until and user.locked_until > now:
            raise AccountLockedError()

        if verified_channel == OTPChannel.EMAIL.value:
            if user.email is None or user.email_verified_at is None:
                raise AccountDisabledError("Email verification is required before login.")
        elif verified_channel == OTPChannel.SMS.value:
            if user.phone_number is None or user.phone_verified_at is None:
                raise AccountDisabledError()

        allowed_statuses = {UserStatus.ACTIVE}
        if allow_pending:
            allowed_statuses.add(UserStatus.PENDING_VERIFICATION)
        if user.status not in allowed_statuses:
            raise AccountDisabledError()

    @staticmethod
    def is_active(user: Users) -> bool:
        """Return whether a user is eligible to receive recovery/login OTPs."""
        return user.status == UserStatus.ACTIVE and user.account_closed_at is None


class PasswordHistoryPolicy:
    """Reject recently used passwords with constant-time password verification."""

    def __init__(self, *, settings: AppSettings, passwords: PasswordManager) -> None:
        self._settings = settings
        self._passwords = passwords

    async def ensure_not_reused(
        self,
        *,
        users: PasswordHistoryRepositoryPort,
        user: Users,
        new_password: str,
    ) -> None:
        """Reject a password found in the configured password history."""
        hashes = await users.recent_password_hashes(
            user_id=user.id,
            limit=self._settings.PASSWORD_HISTORY_COUNT,
        )
        if user.password_hash and user.password_hash not in hashes:
            hashes.insert(0, user.password_hash)
        for password_hash in hashes:
            if await self._passwords.verify(password_hash, new_password):
                raise ValidationError("The new password was used recently.")


class OtpVerificationPolicy:
    """Convert internal OTP failure categories to stable API exceptions."""

    @staticmethod
    def require_valid(result: OTPVerification) -> None:
        """Raise the appropriate API error for an invalid OTP verification result."""
        if result.valid:
            return
        if result.failure is OTPFailure.EXPIRED:
            raise OtpExpiredError()
        if result.failure is OTPFailure.CONSUMED:
            raise OtpAlreadyUsedError()
        if result.failure is OTPFailure.BLOCKED:
            raise OtpAttemptsExceededError()
        raise OtpInvalidError()


def request_uuid(value: str | None) -> uuid.UUID | None:
    """Parse an optional request identifier without raising."""
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


__all__ = [
    "AccountAccessPolicy",
    "OtpVerificationPolicy",
    "PasswordHistoryPolicy",
    "PasswordHistoryRepositoryPort",
    "request_uuid",
]
