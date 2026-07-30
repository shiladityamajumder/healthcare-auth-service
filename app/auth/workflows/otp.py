"""File: app/auth/workflows/otp.py

Purpose:
Coordinates bounded OTP issuance, hashed persistence, row-locked verification,
attempt tracking, expiry, and one-time consumption.

Dependency flow:
Owning service transaction and OTP repository port
-> OTPService issue/verify
-> SecureHashing and OTP policy checks
-> repository lock/update operations
-> issued or verified challenge result

The service coordinates OTP issuance and verification. Each vertical
authentication module supplies a repository implementation through
``OTPRepositoryPort``.

The service never logs plaintext OTP values or complete destinations.
Issuance and verification must run inside the owning module's transaction.
"""

from __future__ import annotations

import math
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

    def add(
        self,
        challenge: OtpChallenges,
    ) -> None:
        """Stage a new challenge in the current transaction."""

        ...


@dataclass(frozen=True, slots=True)
class IssuedOTP:
    """Generated challenge and plaintext code.

    The plaintext code must be returned only to the owning workflow and passed
    directly to the notification boundary. It must never be persisted or
    logged.
    """

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
    """Issue destination-bound, rate-bounded, single-use OTP challenges."""

    def __init__(
        self,
        *,
        settings: AppSettings,
        hashing: SecureHashing,
    ) -> None:
        """Initialize the OTP engine.

        Args:
            settings: Validated OTP policy configuration.
            hashing: Shared secure hashing infrastructure.
        """
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
        """Create one OTP after cooldown and rolling-window checks.

        The caller must execute this operation within a database transaction.
        The repository lock prevents concurrent requests from bypassing resend
        cooldown enforcement.

        Args:
            repository: OTP persistence implementation.
            channel: OTP delivery channel.
            destination: Canonical email or phone destination.
            purpose: Stable OTP workflow purpose.

        Returns:
            Newly staged challenge and its plaintext OTP.

        Raises:
            ValueError: If channel, destination, or purpose is blank.
            RateLimitError: If cooldown or resend limits are exceeded.
        """
        normalized_channel = _required_text(
            channel,
            field_name="channel",
            casefold=True,
        )
        normalized_destination = _required_text(
            destination,
            field_name="destination",
        )
        normalized_purpose = _required_text(
            purpose,
            field_name="purpose",
            casefold=True,
        )

        now = utc_now()

        destination_hash = self._hashing.destination_hash(
            normalized_destination
        )

        # Serialize issuance per destination/purpose before cooldown and resend
        # counters are evaluated.
        await repository.acquire_issue_lock(
            destination_hash=destination_hash,
            purpose=normalized_purpose,
        )

        latest = await repository.latest_for_destination(
            destination_hash=destination_hash,
            purpose=normalized_purpose,
        )

        if latest is not None:
            cooldown_deadline = (
                latest.created_at
                + timedelta(
                    seconds=(
                        self._settings
                        .OTP_RESEND_COOLDOWN_SECONDS
                    )
                )
            )

            if cooldown_deadline > now:
                retry_after_seconds = max(
                    1,
                    math.ceil(
                        (
                            cooldown_deadline - now
                        ).total_seconds()
                    ),
                )

                raise RateLimitError(
                    retry_after_seconds=retry_after_seconds,
                )

        resend_window_start = (
            now
            - timedelta(
                seconds=(
                    self._settings
                    .OTP_RESEND_WINDOW_SECONDS
                )
            )
        )

        recent_count = await repository.count_recent_issues(
            destination_hash=destination_hash,
            purpose=normalized_purpose,
            since=resend_window_start,
        )

        if recent_count >= self._settings.OTP_MAX_RESENDS:
            raise RateLimitError(
                retry_after_seconds=(
                    self._settings
                    .OTP_RESEND_WINDOW_SECONDS
                ),
            )

        # A newly issued challenge supersedes every still-active predecessor.
        await repository.invalidate_active(
            destination_hash=destination_hash,
            purpose=normalized_purpose,
            consumed_at=now,
        )

        challenge_id = uuid.uuid4()
        code = self._hashing.generate_otp()

        challenge = OtpChallenges(
            id=challenge_id,
            channel=normalized_channel,
            destination_hash=destination_hash,
            purpose=normalized_purpose,
            otp_hash=self._hashing.otp_hash(
                challenge_id,
                code,
            ),
            attempts=0,
            max_attempts=self._settings.OTP_MAX_ATTEMPTS,
            expires_at=(
                now
                + timedelta(
                    seconds=self._settings.OTP_TTL_SECONDS
                )
            ),
        )

        repository.add(
            challenge
        )

        return IssuedOTP(
            challenge=challenge,
            code=code,
        )

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
        """Verify and consume a challenge while enforcing attempt limits.

        The challenge row must be locked by the repository so concurrent
        verification attempts cannot bypass attempt or single-use controls.

        Args:
            repository: OTP persistence implementation.
            challenge_id: Challenge being verified.
            channel: Expected OTP channel.
            destination: Expected canonical destination.
            purpose: One acceptable purpose or a collection of purposes.
            code: Submitted plaintext OTP.

        Returns:
            Verification outcome without exposing sensitive values.

        Raises:
            ValueError: If channel, destination, or accepted purposes are
                invalid.
        """
        normalized_channel = _required_text(
            channel,
            field_name="channel",
            casefold=True,
        )
        normalized_destination = _required_text(
            destination,
            field_name="destination",
        )
        accepted_purposes = _normalize_purposes(
            purpose
        )

        # The repository lock makes attempts, blocking, expiry, and consumption
        # atomic across concurrent verification requests.
        challenge = await repository.get_for_update(
            challenge_id
        )

        if challenge is None:
            return OTPVerification(
                valid=False,
                failure=OTPFailure.NOT_FOUND,
            )

        now = utc_now()

        if challenge.blocked_at is not None:
            return OTPVerification(
                valid=False,
                failure=OTPFailure.BLOCKED,
            )

        if challenge.consumed_at is not None:
            return OTPVerification(
                valid=False,
                failure=OTPFailure.CONSUMED,
            )

        if challenge.expires_at <= now:
            challenge.consumed_at = now

            return OTPVerification(
                valid=False,
                failure=OTPFailure.EXPIRED,
            )

        destination_hash = self._hashing.destination_hash(
            normalized_destination
        )

        metadata_matches = (
            challenge.channel.casefold()
            == normalized_channel
            and challenge.purpose.casefold()
            in accepted_purposes
            and challenge.destination_hash
            == destination_hash
        )

        if not metadata_matches:
            return OTPVerification(
                valid=False,
                failure=OTPFailure.MISMATCH,
            )

        code_matches = self._hashing.verify_otp_hash(
            challenge.id,
            code,
            challenge.otp_hash,
        )

        if not code_matches:
            challenge.attempts += 1

            if challenge.attempts >= challenge.max_attempts:
                challenge.blocked_at = now

                return OTPVerification(
                    valid=False,
                    failure=OTPFailure.BLOCKED,
                )

            return OTPVerification(
                valid=False,
                failure=OTPFailure.MISMATCH,
            )

        # Successful verification permanently consumes the one-time challenge.
        challenge.consumed_at = now

        return OTPVerification(
            valid=True,
        )


def _normalize_purposes(
    value: str | Collection[str],
) -> frozenset[str]:
    """Normalize one or more accepted OTP purposes.

    Args:
        value: One purpose or a collection of accepted purposes.

    Returns:
        Normalized immutable purpose collection.

    Raises:
        ValueError: If no valid purposes are provided.
    """
    raw_values = (
        (value,)
        if isinstance(value, str)
        else tuple(value)
    )

    normalized = frozenset(
        _required_text(
            item,
            field_name="purpose",
            casefold=True,
        )
        for item in raw_values
    )

    if not normalized:
        raise ValueError(
            "At least one OTP purpose is required."
        )

    return normalized


def _required_text(
    value: str,
    *,
    field_name: str,
    casefold: bool = False,
) -> str:
    """Normalize one required OTP value.

    Args:
        value: Value requiring validation.
        field_name: Field name included in validation errors.
        casefold: Whether the normalized value should be case-insensitive.

    Returns:
        Validated nonblank value.

    Raises:
        ValueError: If the value is blank or contains control characters.
    """
    normalized = value.strip()

    if not normalized:
        raise ValueError(
            f"{field_name} must not be blank."
        )

    if any(
        ord(character) < 32 or ord(character) == 127
        for character in normalized
    ):
        raise ValueError(
            f"{field_name} contains invalid control characters."
        )

    if casefold:
        normalized = normalized.casefold()

    return normalized


__all__ = [
    "IssuedOTP",
    "OTPFailure",
    "OTPRepositoryPort",
    "OTPService",
    "OTPVerification",
]
