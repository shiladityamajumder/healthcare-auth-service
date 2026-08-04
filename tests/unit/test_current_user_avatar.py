"""Verify secure public-avatar attachment and response projection."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import app.modules.current_user.service as current_user_service
import pytest
from app.common.exceptions import ValidationError
from app.models.enums import UserStatus
from app.modules.current_user.schemas import UpdateCurrentUserRequest
from app.modules.current_user.service import CurrentUserService


class _UnitOfWork:
    session = object()

    async def __aenter__(self) -> _UnitOfWork:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class _Repository:
    def __init__(self, *, avatar_url: str | None) -> None:
        self.avatar_url = avatar_url
        self.avatar_lookups: list[tuple[uuid.UUID, uuid.UUID]] = []
        self.user = SimpleNamespace(
            id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            email="ada@example.com",
            email_verified_at=None,
            phone_country_code=None,
            phone_number=None,
            phone_verified_at=None,
            status=UserStatus.ACTIVE,
            preferred_locale="en-IN",
            timezone="Asia/Kolkata",
        )
        self.profile = SimpleNamespace(
            first_name="Ada",
            last_name="Lovelace",
            preferred_name=None,
            avatar_file_id=None,
            avatar_public_url=None,
            updated_by=None,
        )

    async def get_by_id(self, user_id: uuid.UUID, *, for_update: bool = False) -> Any:
        _ = for_update
        return self.user if user_id == self.user.id else None

    async def get_active_profile(
        self,
        user_id: uuid.UUID,
        *,
        for_update: bool = False,
    ) -> Any:
        _ = for_update
        return self.profile if user_id == self.user.id else None

    async def get_attachable_avatar_url(
        self,
        *,
        file_id: uuid.UUID,
        owner_user_id: uuid.UUID,
    ) -> str | None:
        self.avatar_lookups.append((file_id, owner_user_id))
        return self.avatar_url

    def add_profile(self, profile: Any) -> None:
        self.profile = profile


def _service(monkeypatch: pytest.MonkeyPatch, repository: _Repository) -> CurrentUserService:
    monkeypatch.setattr(
        current_user_service,
        "CurrentUserRepository",
        lambda _session: repository,
    )
    return CurrentUserService(uow=_UnitOfWork())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_update_returns_resolved_public_avatar(monkeypatch: pytest.MonkeyPatch) -> None:
    repository = _Repository(avatar_url="https://cdn.example.com/avatars/ada.webp")
    service = _service(monkeypatch, repository)
    file_id = uuid.UUID("22222222-2222-2222-2222-222222222222")

    response = await service.update(
        user_id=repository.user.id,
        payload=UpdateCurrentUserRequest(avatar_file_id=file_id),
    )

    assert repository.avatar_lookups == [(file_id, repository.user.id)]
    assert response.profile is not None
    assert response.profile.avatar is not None
    assert response.profile.avatar.id == file_id
    assert str(response.profile.avatar.url) == "https://cdn.example.com/avatars/ada.webp"


@pytest.mark.asyncio
async def test_update_rejects_file_that_is_not_an_attachable_avatar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _Repository(avatar_url=None)
    service = _service(monkeypatch, repository)

    with pytest.raises(ValidationError, match="available public image"):
        await service.update(
            user_id=repository.user.id,
            payload=UpdateCurrentUserRequest(
                avatar_file_id=uuid.UUID("22222222-2222-2222-2222-222222222222")
            ),
        )

    assert repository.profile.avatar_file_id is None


@pytest.mark.asyncio
async def test_update_can_clear_avatar_without_resolving_a_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _Repository(avatar_url=None)
    repository.profile.avatar_file_id = uuid.UUID(
        "22222222-2222-2222-2222-222222222222"
    )
    repository.profile.avatar_public_url = "https://cdn.example.com/avatars/old.webp"
    service = _service(monkeypatch, repository)

    response = await service.update(
        user_id=repository.user.id,
        payload=UpdateCurrentUserRequest(avatar_file_id=None),
    )

    assert repository.avatar_lookups == []
    assert response.profile is not None
    assert response.profile.avatar is None
