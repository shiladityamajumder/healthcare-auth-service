"""Login token-response compatibility tests."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast

import pytest
from app.auth.request_context.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.auth.security.passwords import PasswordManager
from app.auth.security.tokens import TokenManager
from app.models.enums import UserStatus
from app.models.identity import Sessions, Users
from app.modules.login.service import PasswordLoginService
from tests.conftest import build_test_settings


class _FakeRepository:
    def __init__(self) -> None:
        self.sessions: list[Sessions] = []

    async def authorization_claims(
        self,
        *,
        user_id: uuid.UUID,
        now: object,
    ) -> SimpleNamespace:
        _ = user_id, now
        return SimpleNamespace(
            roles=("customer",),
            permissions=("orders.read",),
        )

    async def get_active_profile(self, user_id: uuid.UUID) -> None:
        _ = user_id
        return None

    def add_session(self, session_record: Sessions) -> None:
        self.sessions.append(session_record)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response_version", "contains_authorization"),
    [(1, True), (2, False)],
)
async def test_login_uses_explicit_response_version(
    response_version: int,
    contains_authorization: bool,
) -> None:
    settings = build_test_settings(
        AUTH_LOGIN_REFRESH_RESPONSE_VERSION=response_version,
    )
    service = PasswordLoginService(
        uow=cast(Any, object()),
        settings=settings,
        passwords=PasswordManager(settings),
        hashing=SecureHashing(settings),
        tokens=TokenManager(settings),
    )
    repository = _FakeRepository()
    user = Users(
        id=uuid.uuid4(),
        email="customer@example.com",
        email_normalized="customer@example.com",
        email_verified_at=None,
        status=UserStatus.ACTIVE,
        preferred_locale="en-IN",
        timezone="Asia/Kolkata",
    )

    result = await service._issue_tokens(
        user=user,
        repository=cast(Any, repository),
        context=AuthRequestContext(),
        auth_method="password",
    )
    user_data = result.user.model_dump()

    assert ("roles" in user_data) is contains_authorization
    assert ("permissions" in user_data) is contains_authorization
    assert len(repository.sessions) == 1
