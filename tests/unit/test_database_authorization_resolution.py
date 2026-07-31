"""Bearer principals resolve authorization from current database state."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from app.auth.authorization.claims import AuthorizationClaims
from app.auth.request_context.context import AuthRequestContext
from app.auth.request_context.dependencies import get_current_user_principal
from app.models.enums import UserStatus
from app.models.identity import Sessions, Users
from app.utils.datetime_utils import utc_now
from fastapi.security import HTTPAuthorizationCredentials
from tests.conftest import build_test_settings


class _FakeTokens:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def decode(self, token: str, *, expected_type: object) -> dict[str, object]:
        _ = token, expected_type
        return self.payload


class _FakeResult:
    def __init__(self, row: tuple[Sessions, Users]) -> None:
        self._row = row

    def one_or_none(self) -> tuple[Sessions, Users]:
        return self._row


class _FakeSession:
    def __init__(self, row: tuple[Sessions, Users]) -> None:
        self._row = row

    async def execute(self, statement: object) -> _FakeResult:
        _ = statement
        return _FakeResult(self._row)


class _FakeDatabase:
    def __init__(self, row: tuple[Sessions, Users]) -> None:
        self._row = row

    @asynccontextmanager
    async def session(self) -> AsyncIterator[_FakeSession]:
        yield _FakeSession(self._row)


@pytest.mark.asyncio
async def test_principal_reflects_subsequent_database_authorization_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = utc_now()
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    user = Users(
        id=user_id,
        email="user@example.com",
        email_normalized="user@example.com",
        status=UserStatus.ACTIVE,
    )
    session = Sessions(
        id=session_id,
        user_id=user_id,
        refresh_token_hash="hash",  # noqa: S106 - inert persisted digest fixture
        token_family_id=uuid.uuid4(),
        expires_at=now + timedelta(hours=1),
        last_seen_at=now,
    )
    current_claims = AuthorizationClaims(
        roles=("customer",),
        permissions=("orders.read",),
    )

    async def load_current_claims(*args: object, **kwargs: object) -> AuthorizationClaims:
        _ = args, kwargs
        return current_claims

    monkeypatch.setattr(
        "app.auth.request_context.dependencies.load_authorization_claims",
        load_current_claims,
    )
    runtime = SimpleNamespace(
        settings=build_test_settings(),
        tokens=_FakeTokens(
            {
                "sub": str(user_id),
                "sid": str(session_id),
                "amr": ["password"],
            }
        ),
    )
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="signed-token",
    )
    database = _FakeDatabase((session, user))

    first = await get_current_user_principal(
        credentials=credentials,
        database=cast(Any, database),
        runtime=cast(Any, runtime),
        context=AuthRequestContext(),
    )
    current_claims = AuthorizationClaims(
        roles=("customer", "doctor"),
        permissions=("clinical.prescriptions.issue",),
    )
    second = await get_current_user_principal(
        credentials=credentials,
        database=cast(Any, database),
        runtime=cast(Any, runtime),
        context=AuthRequestContext(),
    )

    assert first.roles == frozenset({"customer"})
    assert first.permissions == frozenset({"orders.read"})
    assert second.roles == frozenset({"customer", "doctor"})
    assert second.permissions == frozenset({"clinical.prescriptions.issue"})
