"""Password-reset session invalidation and one-time proof tests."""

from __future__ import annotations

import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, Self, cast

import pytest
from app.auth.request_context.context import AuthRequestContext
from app.common.exceptions import AuthenticationError
from app.models.enums import OTPPurpose, UserStatus
from app.models.identity import OtpChallenges, Sessions, Users
from app.modules.password_management.schemas import ResetPasswordWithTokenRequest
from app.modules.password_management.service import PasswordManagementService
from app.utils.datetime_utils import utc_now
from tests.conftest import build_test_settings


class _FakeUnitOfWork:
    session = object()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        _ = args


class _FakePasswords:
    def validate_strength(self, password: str, **kwargs: object) -> None:
        _ = password, kwargs

    async def verify(self, password_hash: str, password: str) -> bool:
        _ = password_hash, password
        return False

    async def hash(self, password: str) -> str:
        _ = password
        return "$argon2id$replacement"


class _FakeHashing:
    def token_hash(self, token: str) -> str:
        return f"hash:{token}"

    def destination_hash(self, destination: str) -> str:
        _ = destination
        return "destination-hash"


class _FakeTokens:
    def __init__(self, *, user_id: uuid.UUID, challenge_id: uuid.UUID) -> None:
        self._claims = {
            "sub": str(user_id),
            "challenge_id": str(challenge_id),
            "destination_hash": "destination-hash",
            "channel": "email",
        }

    def decode(self, token: str, *, expected_type: object) -> dict[str, str]:
        _ = token, expected_type
        return self._claims

    def create_refresh_token(self, **kwargs: object) -> SimpleNamespace:
        _ = kwargs
        return SimpleNamespace(
            token="r" * 64,
            expires_at=utc_now() + timedelta(days=30),
        )

    def create_access_token(self, **kwargs: object) -> SimpleNamespace:
        _ = kwargs
        return SimpleNamespace(
            token="a" * 64,
            expires_at=utc_now() + timedelta(minutes=15),
        )


class _FakeRepository:
    def __init__(self, *, user: Users, challenge: OtpChallenges) -> None:
        self.user = user
        self.challenge = challenge
        self.events: list[str] = []

    async def get_for_update(self, challenge_id: uuid.UUID) -> OtpChallenges:
        assert challenge_id == self.challenge.id
        return self.challenge

    async def get_by_id(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Users:
        assert user_id == self.user.id
        assert for_update is True
        return self.user

    async def recent_password_hashes(
        self,
        *,
        user_id: uuid.UUID,
        limit: int,
    ) -> list[str]:
        _ = user_id, limit
        return []

    def update_password_hash(self, user: Users, password_hash: str) -> None:
        user.password_hash = password_hash

    def reset_failed_login_count(self, user: Users) -> None:
        user.failed_login_count = 0

    def add_password_history(self, *, user_id: uuid.UUID, password_hash: str) -> None:
        _ = user_id, password_hash

    async def revoke_user_sessions(
        self,
        *,
        user_id: uuid.UUID,
        revoked_at: object,
        reason: str,
    ) -> int:
        _ = user_id, revoked_at
        assert reason == "password_reset"
        self.events.append("revoke_sessions")
        return 2

    async def authorization_claims(
        self,
        *,
        user_id: uuid.UUID,
        now: object,
    ) -> SimpleNamespace:
        _ = user_id, now
        return SimpleNamespace(roles=("customer",), permissions=())

    async def get_active_profile(self, user_id: uuid.UUID) -> None:
        _ = user_id
        return None

    def add_session(self, session_record: Sessions) -> None:
        _ = session_record
        self.events.append("issue_replacement_session")


@pytest.mark.asyncio
async def test_password_reset_proof_revokes_sessions_before_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = utc_now()
    user = Users(
        id=uuid.uuid4(),
        email="customer@example.com",
        email_normalized="customer@example.com",
        email_verified_at=now,
        status=UserStatus.ACTIVE,
        preferred_locale="en-IN",
        timezone="Asia/Kolkata",
        password_hash="$argon2id$old",  # noqa: S106 - inert encoded-hash fixture
    )
    challenge = OtpChallenges(
        id=uuid.uuid4(),
        channel="email",
        destination_hash="destination-hash",
        purpose=OTPPurpose.PASSWORD_RESET_EMAIL.value,
        otp_hash="otp-hash",
        attempts=0,
        max_attempts=5,
        expires_at=now + timedelta(minutes=5),
        consumed_at=now,
        blocked_at=None,
    )
    repository = _FakeRepository(user=user, challenge=challenge)
    monkeypatch.setattr(
        "app.modules.password_management.service.PasswordRepository",
        lambda _: repository,
    )
    settings = build_test_settings()
    service = PasswordManagementService(
        uow=cast(Any, _FakeUnitOfWork()),
        settings=settings,
        passwords=cast(Any, _FakePasswords()),
        hashing=cast(Any, _FakeHashing()),
        tokens=cast(
            Any,
            _FakeTokens(user_id=user.id, challenge_id=challenge.id),
        ),
        otp=cast(Any, object()),
        notifications=cast(Any, object()),
    )

    await service.reset_with_token(
        ResetPasswordWithTokenRequest(
            reset_token="t" * 64,
            new_password="NewSecurePassword!123",  # noqa: S106 - test input
        ),
        AuthRequestContext(),
    )

    assert repository.events == [
        "revoke_sessions",
        "issue_replacement_session",
    ]
    assert challenge.blocked_at is not None

    with pytest.raises(AuthenticationError):
        await service.reset_with_token(
            ResetPasswordWithTokenRequest(
                reset_token="t" * 64,
                new_password="AnotherSecurePassword!456",  # noqa: S106 - test input
            ),
            AuthRequestContext(),
        )
    assert repository.events == [
        "revoke_sessions",
        "issue_replacement_session",
    ]
