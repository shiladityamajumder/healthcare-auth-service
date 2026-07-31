"""Current-authorization service tests."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, Self, cast

import pytest
from app.common.exceptions import AuthenticationError
from app.modules.current_user.service import CurrentUserService


class _FakeUnitOfWork:
    session = object()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        _ = args


class _FakeRepository:
    def __init__(self, user_id: uuid.UUID, *, session_active: bool = True) -> None:
        self.user_id = user_id
        self.session_active = session_active
        self.authorization_calls = 0
        self.session_checks = 0

    async def get_by_id(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> SimpleNamespace | None:
        _ = for_update
        return SimpleNamespace(id=user_id) if user_id == self.user_id else None

    async def authorization_claims(
        self,
        *,
        user_id: uuid.UUID,
        now: object,
    ) -> SimpleNamespace:
        _ = user_id, now
        self.authorization_calls += 1
        return SimpleNamespace(
            roles=("doctor", "customer", "doctor"),
            permissions=("prescriptions.read", "orders.read", "orders.read"),
        )

    async def active_session_exists(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
        now: object,
    ) -> bool:
        _ = user_id, session_id, now
        self.session_checks += 1
        return self.session_active


@pytest.mark.asyncio
async def test_current_authorization_is_database_resolved_sorted_and_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid.uuid4()
    repository = _FakeRepository(user_id)
    monkeypatch.setattr(
        "app.modules.current_user.service.CurrentUserRepository",
        lambda _: repository,
    )
    service = CurrentUserService(uow=cast(Any, _FakeUnitOfWork()))
    session_id = uuid.uuid4()

    result = await service.authorization(
        user_id=user_id,
        session_id=session_id,
    )

    assert result.roles == ["customer", "doctor"]
    assert result.permissions == ["orders.read", "prescriptions.read"]
    assert repository.authorization_calls == 1
    assert repository.session_checks == 1


@pytest.mark.asyncio
async def test_legacy_role_and_permission_projections_delegate_to_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid.uuid4()
    repository = _FakeRepository(user_id)
    monkeypatch.setattr(
        "app.modules.current_user.service.CurrentUserRepository",
        lambda _: repository,
    )
    service = CurrentUserService(uow=cast(Any, _FakeUnitOfWork()))
    session_id = uuid.uuid4()

    roles = await service.roles(user_id=user_id, session_id=session_id)
    permissions = await service.permissions(
        user_id=user_id,
        session_id=session_id,
    )

    assert roles.roles == ["customer", "doctor"]
    assert permissions.permissions == ["orders.read", "prescriptions.read"]
    assert repository.authorization_calls == 2


@pytest.mark.asyncio
async def test_current_authorization_rejects_inactive_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user_id = uuid.uuid4()
    repository = _FakeRepository(user_id, session_active=False)
    monkeypatch.setattr(
        "app.modules.current_user.service.CurrentUserRepository",
        lambda _: repository,
    )
    service = CurrentUserService(uow=cast(Any, _FakeUnitOfWork()))

    with pytest.raises(AuthenticationError):
        await service.authorization(
            user_id=user_id,
            session_id=uuid.uuid4(),
        )

    assert repository.authorization_calls == 0
