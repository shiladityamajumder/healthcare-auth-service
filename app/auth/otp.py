"""Reusable OTP challenge generation and verification infrastructure.

The service is persistence-agnostic. Each vertical module supplies its own
repository implementation through the protocol below.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from app.auth.security.hashing import SecureHashing
from app.common.exceptions import RateLimitError
from app.core.config import AppSettings
from app.models.identity import OtpChallenges
from app.utils.datetime_utils import utc_now


class OTPRepositoryPort(Protocol):
    """Persistence operations required by the shared OTP engine."""

    async def acquire_issue_lock(
        self,
        *,
        destination_hash: str,
        purpose: str,
    ) -> None:
        """Acquire a transaction-scoped lock for OTP issuance."""
        ...

    async def latest_for_destination(
        self,
        *,
        destination_hash: str,
        purpose: str,
    ) -> OtpChallenges | None:
        """Load the latest challenge for a destination and purpose."""
        ...

    async def count_recent_issues(
        self,
        *,
        destination_hash: str,
        purpose: str,
        since: datetime,
    ) -> int:
        """Count recently issued challenges for rate enforcement."""
        ...

    async def invalidate_active(
        self,
        *,
        destination_hash: str,
        purpose: str,
        consumed_at: datetime,
    ) -> int:
        """Consume active challenges for a destination and purpose."""
        ...

    async def get_for_update(
        self,
        challenge_id: uuid.UUID,
    ) -> OtpChallenges | None:
        """Load and lock one challenge for verification."""
        ...

    def add(self, challenge: OtpChallenges) -> None:
        """Stage a new challenge in the current unit of work."""
        ...


@dataclass(frozen=True, slots=True)
class IssuedOTP:
    """Generated challenge and plaintext code returned only to the caller."""

    challenge: OtpChallenges
    code: str


class OTPFailure(StrEnum):
    """Non-sensitive OTP verification failure categories."""

    NOT_FOUND = "OTP_CHALLENGE_NOT_FOUND"
    MISMATCH = "OTP_INVALID"
    EXPIRED = "OTP_EXPIRED"
    CONSUMED = "OTP_ALREADY_USED"
    BLOCKED = "OTP_BLOCKED"


@dataclass(frozen=True, slots=True)
class OTPVerification:
    """Result returned by the OTP verifier."""

    valid: bool
    failure: OTPFailure | None = None


class OTPService:
    """Issue rate-bounded, destination-bound and single-use OTP challenges."""

    def __init__(self, *, settings: AppSettings, hashing: SecureHashing) -> None:
        self._settings = settings
        self._hashing = hashing

    async def issue(
        self,
        *,
        repository: OTPRepositoryPort,
        channel: str,
        destination: str,
        purpose: str,
    ) -> IssuedOTP:
        """Create one OTP after cooldown and rolling-window checks."""
        now = utc_now()
        destination_hash = self._hashing.destination_hash(destination)
        await repository.acquire_issue_lock(
            destination_hash=destination_hash,
            purpose=purpose,
        )
        latest = await repository.latest_for_destination(
            destination_hash=destination_hash,
            purpose=purpose,
        )
        if latest and latest.created_at + timedelta(
            seconds=self._settings.OTP_RESEND_COOLDOWN_SECONDS
        ) > now:
            retry_after = max(
                1,
                int(
                    (
                        latest.created_at
                        + timedelta(
                            seconds=self._settings.OTP_RESEND_COOLDOWN_SECONDS
                        )
                        - now
                    ).total_seconds()
                ),
            )
            raise RateLimitError(
                "An OTP was requested too recently.",
                retry_after_seconds=retry_after,
            )

        recent_count = await repository.count_recent_issues(
            destination_hash=destination_hash,
            purpose=purpose,
            since=now
            - timedelta(seconds=self._settings.OTP_RESEND_WINDOW_SECONDS),
        )
        if recent_count >= self._settings.OTP_MAX_RESENDS:
            raise RateLimitError(
                "OTP resend limit exceeded.",
                retry_after_seconds=self._settings.OTP_RESEND_WINDOW_SECONDS,
            )

        await repository.invalidate_active(
            destination_hash=destination_hash,
            purpose=purpose,
            consumed_at=now,
        )
        challenge_id = uuid.uuid4()
        code = self._hashing.generate_otp()
        challenge = OtpChallenges(
            id=challenge_id,
            channel=channel,
            destination_hash=destination_hash,
            purpose=purpose,
            otp_hash=self._hashing.otp_hash(challenge_id, code),
            attempts=0,
            max_attempts=self._settings.OTP_MAX_ATTEMPTS,
            expires_at=now + timedelta(seconds=self._settings.OTP_TTL_SECONDS),
        )
        repository.add(challenge)
        return IssuedOTP(challenge=challenge, code=code)

    async def verify(
        self,
        *,
        repository: OTPRepositoryPort,
        challenge_id: uuid.UUID,
        channel: str,
        destination: str,
        purpose: str | Collection[str],
        code: str,
    ) -> OTPVerification:
        """Verify and consume a challenge while enforcing its attempt limit."""
        challenge = await repository.get_for_update(challenge_id)
        if challenge is None:
            return OTPVerification(valid=False, failure=OTPFailure.NOT_FOUND)
        now = utc_now()
        if challenge.blocked_at is not None:
            return OTPVerification(valid=False, failure=OTPFailure.BLOCKED)
        if challenge.consumed_at is not None:
            return OTPVerification(valid=False, failure=OTPFailure.CONSUMED)
        if challenge.expires_at <= now:
            challenge.consumed_at = now
            return OTPVerification(valid=False, failure=OTPFailure.EXPIRED)

        purposes = {purpose} if isinstance(purpose, str) else set(purpose)
        destination_hash = self._hashing.destination_hash(destination)
        if (
            challenge.channel != channel
            or challenge.purpose not in purposes
            or challenge.destination_hash != destination_hash
        ):
            return OTPVerification(valid=False, failure=OTPFailure.MISMATCH)

        if not self._hashing.verify_otp_hash(challenge.id, code, challenge.otp_hash):
            challenge.attempts += 1
            if challenge.attempts >= challenge.max_attempts:
                challenge.blocked_at = now
                return OTPVerification(valid=False, failure=OTPFailure.BLOCKED)
            return OTPVerification(valid=False, failure=OTPFailure.MISMATCH)

        challenge.consumed_at = now
        return OTPVerification(valid=True)


__all__ = [
    "IssuedOTP",
    "OTPFailure",
    "OTPRepositoryPort",
    "OTPService",
    "OTPVerification",
]
