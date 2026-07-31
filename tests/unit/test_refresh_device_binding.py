"""Refresh-token tests for immutable persisted session device identity."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, Self, cast

import pytest
from app.api.exception_handlers import app_error_handler
from app.auth.request_context.context import AuthRequestContext
from app.common.exceptions import (
    AuthenticationError,
    RefreshTokenReuseError,
    SessionRevokedError,
)
from app.models.enums import UserStatus
from app.models.identity import Sessions, Users
from app.modules.token_management.schemas import RefreshTokenRequest
from app.modules.token_management.service import TokenManagementService
from app.utils.datetime_utils import utc_now
from starlette.requests import Request

REFRESH_TOKEN = "r" * 64


class _FakeUnitOfWork:
    session = object()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        _ = args


class _SerializedFakeUnitOfWork(_FakeUnitOfWork):
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> Self:
        await self._lock.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        _ = args
        self._lock.release()


class _FakeHashing:
    def token_hash(self, token: str) -> str:
        return f"hash:{token}"


class _FakeTokens:
    def __init__(self, *, user_id: uuid.UUID, session_id: uuid.UUID, family_id: uuid.UUID):
        self.claims = {
            "sub": str(user_id),
            "sid": str(session_id),
            "fam": str(family_id),
        }
        self.rotation_count = 0

    def decode(self, token: str, *, expected_type: object) -> dict[str, str]:
        _ = token, expected_type
        return self.claims

    def create_refresh_token(self, **kwargs: object) -> SimpleNamespace:
        _ = kwargs
        self.rotation_count += 1
        return SimpleNamespace(
            token="n" * 64,
            expires_at=utc_now() + timedelta(days=30),
        )

    def create_access_token(self, **kwargs: object) -> SimpleNamespace:
        _ = kwargs
        return SimpleNamespace(
            token="a" * 64,
            expires_at=utc_now() + timedelta(minutes=15),
        )


class _FakeRepository:
    def __init__(self, *, session: Sessions, user: Users) -> None:
        self.session = session
        self.user = user
        self.session_lock_requested = False
        self.user_session_revocations: list[tuple[uuid.UUID, uuid.UUID | None, str]] = []

    async def get_session(
        self,
        session_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Sessions:
        _ = session_id
        self.session_lock_requested = for_update
        return self.session

    async def get_user(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Users:
        _ = user_id, for_update
        return self.user

    async def get_active_profile(self, user_id: uuid.UUID) -> None:
        _ = user_id
        return None

    async def revoke_family(
        self,
        *,
        family_id: uuid.UUID,
        revoked_at: object,
        reason: str,
    ) -> int:
        _ = revoked_at
        if family_id != self.session.token_family_id:
            return 0
        self.session.revoked_at = utc_now()
        self.session.revoke_reason = reason
        return 1

    async def revoke_user_sessions(
        self,
        *,
        user_id: uuid.UUID,
        revoked_at: object,
        reason: str,
        except_session_id: uuid.UUID | None = None,
    ) -> int:
        _ = revoked_at
        self.user_session_revocations.append((user_id, except_session_id, reason))
        return 1


def _records(
    *,
    stored_device_id: str | None,
    stored_device_type: str | None = "phone",
) -> tuple[Sessions, Users]:
    now = utc_now()
    user_id = uuid.uuid4()
    session = Sessions(
        id=uuid.uuid4(),
        user_id=user_id,
        refresh_token_hash=f"hash:{REFRESH_TOKEN}",
        token_family_id=uuid.uuid4(),
        device_id=stored_device_id,
        device_type=stored_device_type,
        expires_at=now + timedelta(days=1),
        last_seen_at=now,
    )
    user = Users(
        id=user_id,
        email="customer@example.com",
        email_normalized="customer@example.com",
        status=UserStatus.ACTIVE,
        email_verified_at=now,
        preferred_locale="en-IN",
        timezone="Asia/Kolkata",
    )
    return session, user


def _service(
    monkeypatch: pytest.MonkeyPatch,
    *,
    session: Sessions,
    user: Users,
    uow: _FakeUnitOfWork | None = None,
) -> tuple[TokenManagementService, _FakeTokens, _FakeRepository]:
    repository = _FakeRepository(session=session, user=user)
    tokens = _FakeTokens(
        user_id=user.id,
        session_id=session.id,
        family_id=session.token_family_id,
    )
    monkeypatch.setattr(
        "app.modules.token_management.service.TokenRepository",
        lambda _: repository,
    )
    service = TokenManagementService(
        uow=cast(Any, uow or _FakeUnitOfWork()),
        hashing=cast(Any, _FakeHashing()),
        tokens=cast(Any, tokens),
    )
    return service, tokens, repository


@pytest.mark.asyncio
async def test_refresh_returns_minimal_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, user = _records(stored_device_id="device-a")
    service, _, _ = _service(
        monkeypatch,
        session=session,
        user=user,
    )

    result = await service.refresh(
        RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
        AuthRequestContext(device_id="device-a"),
    )

    assert "roles" not in result.user.model_dump()
    assert "permissions" not in result.user.model_dump()


@pytest.mark.asyncio
@pytest.mark.parametrize("incoming_device_id", ["device-a", None])
async def test_refresh_accepts_matching_or_omitted_device_id(
    monkeypatch: pytest.MonkeyPatch,
    incoming_device_id: str | None,
) -> None:
    session, user = _records(stored_device_id="device-a")
    service, tokens, _ = _service(monkeypatch, session=session, user=user)

    await service.refresh(
        RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
        AuthRequestContext(
            device_id=incoming_device_id,
            device_type="tablet",
            platform="android",
        ),
    )

    assert tokens.rotation_count == 1
    assert session.device_id == "device-a"
    assert session.device_type == "phone"


@pytest.mark.asyncio
async def test_refresh_rejects_mismatching_device_id_with_generic_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, user = _records(stored_device_id="device-a")
    original_hash = session.refresh_token_hash
    service, tokens, _ = _service(monkeypatch, session=session, user=user)

    with pytest.raises(AuthenticationError) as raised:
        await service.refresh(
            RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
            AuthRequestContext(device_id="device-b"),
        )

    response = await app_error_handler(
        Request({"type": "http", "method": "POST", "headers": []}),
        raised.value,
    )
    response_body = json.loads(response.body)
    assert response.status_code == 401
    assert response_body["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert "device-a" not in response.body.decode()
    assert "device-b" not in response.body.decode()
    assert tokens.rotation_count == 0
    assert session.refresh_token_hash == original_hash
    assert session.device_id == "device-a"


@pytest.mark.asyncio
async def test_refresh_cannot_change_the_session_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, user = _records(stored_device_id="device-a")
    service, tokens, _ = _service(monkeypatch, session=session, user=user)
    tokens.claims["sub"] = str(uuid.uuid4())

    with pytest.raises(AuthenticationError):
        await service.refresh(
            RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
            AuthRequestContext(device_id="device-a"),
        )

    assert tokens.rotation_count == 0


@pytest.mark.asyncio
async def test_refresh_does_not_bind_first_time_device_id_to_unbound_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, user = _records(
        stored_device_id=None,
        stored_device_type=None,
    )
    service, tokens, _ = _service(monkeypatch, session=session, user=user)

    await service.refresh(
        RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
        AuthRequestContext(
            device_id="new-device",
            device_type="phone",
            platform="ios",
        ),
    )

    assert tokens.rotation_count == 1
    assert session.device_id is None
    assert session.device_type is None


@pytest.mark.asyncio
async def test_refresh_replay_revokes_the_token_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, user = _records(stored_device_id="device-a")
    service, _, repository = _service(
        monkeypatch,
        session=session,
        user=user,
    )

    await service.refresh(
        RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
        AuthRequestContext(device_id="device-a"),
    )
    with pytest.raises(RefreshTokenReuseError):
        await service.refresh(
            RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
            AuthRequestContext(device_id="device-a"),
        )

    assert repository.session_lock_requested is True
    assert session.revoked_at is not None
    assert session.revoke_reason == "refresh_token_reuse_detected"


@pytest.mark.asyncio
async def test_simultaneous_refresh_attempts_have_one_success_and_one_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, user = _records(stored_device_id="device-a")
    service, _, _ = _service(
        monkeypatch,
        session=session,
        user=user,
        uow=_SerializedFakeUnitOfWork(),
    )

    results = await asyncio.gather(
        service.refresh(
            RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
            AuthRequestContext(device_id="device-a"),
        ),
        service.refresh(
            RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
            AuthRequestContext(device_id="device-a"),
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, RefreshTokenReuseError) for result in results) == 1
    assert session.revoke_reason == "refresh_token_reuse_detected"


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["revoked", "expired"])
async def test_revoked_or_expired_session_cannot_refresh(
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    session, user = _records(stored_device_id="device-a")
    if state == "revoked":
        session.revoked_at = utc_now()
    else:
        session.expires_at = utc_now() - timedelta(seconds=1)
    service, tokens, _ = _service(monkeypatch, session=session, user=user)

    with pytest.raises(SessionRevokedError):
        await service.refresh(
            RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
            AuthRequestContext(device_id="device-a"),
        )

    assert tokens.rotation_count == 0


@pytest.mark.asyncio
async def test_deleted_session_cannot_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, user = _records(stored_device_id="device-a")
    service, tokens, repository = _service(
        monkeypatch,
        session=session,
        user=user,
    )
    cast(Any, repository).session = None

    with pytest.raises(AuthenticationError):
        await service.refresh(
            RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
            AuthRequestContext(device_id="device-a"),
        )

    assert tokens.rotation_count == 0


@pytest.mark.asyncio
async def test_disabled_user_cannot_refresh_and_session_is_revoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, user = _records(stored_device_id="device-a")
    user.status = UserStatus.SUSPENDED
    service, tokens, _ = _service(monkeypatch, session=session, user=user)

    with pytest.raises(AuthenticationError):
        await service.refresh(
            RefreshTokenRequest(refresh_token=REFRESH_TOKEN),
            AuthRequestContext(device_id="device-a"),
        )

    assert tokens.rotation_count == 0
    assert session.revoked_at is not None
    assert session.revoke_reason == "account_not_available"


@pytest.mark.asyncio
async def test_logout_all_and_others_scope_session_revocation(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    session, user = _records(stored_device_id="device-a")
    service, _, repository = _service(monkeypatch, session=session, user=user)

    await service.logout_others(
        user_id=user.id,
        current_session_id=session.id,
    )
    await service.logout_all(user_id=user.id)

    assert repository.user_session_revocations == [
        (user.id, session.id, "user_logout_others"),
        (user.id, None, "user_logout_all"),
    ]
    events = {getattr(record, "event", None) for record in caplog.records}
    assert {"other_sessions_logged_out", "all_sessions_logged_out"}.issubset(events)
    assert REFRESH_TOKEN not in caplog.text
