"""File: tests/unit/test_auth_otp.py

Purpose:
Verifies OTP purpose binding, expiry, attempt blocking, and single-use
consumption invariants.

Dependency flow:
In-memory OTP repository and test settings
-> OTPService issue/verify
-> challenge-state mutation
-> security assertions
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.models.identity import OtpChallenges
from app.auth.security.hashing import SecureHashing
from app.auth.workflows.otp import OTPFailure, OTPService
from app.utils.datetime_utils import utc_now
from tests.conftest import build_test_settings


class ChallengeRepository:
    def __init__(self, challenge: OtpChallenges) -> None:
        self.challenge = challenge

    async def get_for_update(self, challenge_id: uuid.UUID) -> OtpChallenges | None:
        return self.challenge if self.challenge.id == challenge_id else None


def challenge_for(
    *,
    hashing: SecureHashing,
    code: str = "123456",
    purpose: str = "login_email",
    max_attempts: int = 2,
    expired: bool = False,
) -> OtpChallenges:
    challenge_id = uuid.uuid4()
    now = utc_now()
    return OtpChallenges(
        id=challenge_id,
        channel="email",
        destination_hash=hashing.destination_hash("user@example.com"),
        purpose=purpose,
        otp_hash=hashing.otp_hash(challenge_id, code),
        attempts=0,
        max_attempts=max_attempts,
        expires_at=now - timedelta(seconds=1) if expired else now + timedelta(minutes=5),
        consumed_at=None,
        blocked_at=None,
        created_at=now,
        updated_at=now,
        row_version=1,
    )


@pytest.mark.asyncio
async def test_otp_purpose_mismatch_cannot_authenticate() -> None:
    """Prevent a valid challenge from crossing workflow-purpose boundaries."""
    settings = build_test_settings()
    hashing = SecureHashing(settings)
    service = OTPService(settings=settings, hashing=hashing)
    challenge = challenge_for(hashing=hashing, purpose="registration_email")
    result = await service.verify(
        repository=ChallengeRepository(challenge),
        challenge_id=challenge.id,
        channel="email",
        destination="user@example.com",
        purpose="login_email",
        code="123456",
    )
    assert result.valid is False
    assert result.failure is OTPFailure.MISMATCH


@pytest.mark.asyncio
async def test_otp_is_single_use() -> None:
    """Require successful verification to consume the challenge permanently."""
    settings = build_test_settings()
    hashing = SecureHashing(settings)
    service = OTPService(settings=settings, hashing=hashing)
    challenge = challenge_for(hashing=hashing)
    repository = ChallengeRepository(challenge)
    first = await service.verify(
        repository=repository,
        challenge_id=challenge.id,
        channel="email",
        destination="user@example.com",
        purpose="login_email",
        code="123456",
    )
    second = await service.verify(
        repository=repository,
        challenge_id=challenge.id,
        channel="email",
        destination="user@example.com",
        purpose="login_email",
        code="123456",
    )
    assert first.valid is True
    assert second.failure is OTPFailure.CONSUMED


@pytest.mark.asyncio
async def test_otp_blocks_after_maximum_attempts() -> None:
    """Require failed attempts to block a challenge at the configured maximum."""
    settings = build_test_settings(OTP_MAX_ATTEMPTS=2)
    hashing = SecureHashing(settings)
    service = OTPService(settings=settings, hashing=hashing)
    challenge = challenge_for(hashing=hashing, max_attempts=2)
    repository = ChallengeRepository(challenge)
    first = await service.verify(
        repository=repository,
        challenge_id=challenge.id,
        channel="email",
        destination="user@example.com",
        purpose="login_email",
        code="000000",
    )
    second = await service.verify(
        repository=repository,
        challenge_id=challenge.id,
        channel="email",
        destination="user@example.com",
        purpose="login_email",
        code="000000",
    )
    assert first.failure is OTPFailure.MISMATCH
    assert second.failure is OTPFailure.BLOCKED
    assert challenge.blocked_at is not None


@pytest.mark.asyncio
async def test_expired_otp_is_consumed() -> None:
    """Require expiry detection to consume the unusable challenge state."""
    settings = build_test_settings()
    hashing = SecureHashing(settings)
    service = OTPService(settings=settings, hashing=hashing)
    challenge = challenge_for(hashing=hashing, expired=True)
    result = await service.verify(
        repository=ChallengeRepository(challenge),
        challenge_id=challenge.id,
        channel="email",
        destination="user@example.com",
        purpose="login_email",
        code="123456",
    )
    assert result.failure is OTPFailure.EXPIRED
    assert challenge.consumed_at is not None
