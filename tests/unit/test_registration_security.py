"""Security tests for server-controlled public registration roles."""

from __future__ import annotations

import uuid
from typing import Any, cast

import pytest
from app.common.exceptions import InfrastructureUnavailableError
from app.core.config import AppSettings
from app.models.identity import Roles
from app.modules.registration.service import _RegistrationWriter

BASE_SETTINGS = {
    "_env_file": None,
    "POSTGRES_URL": "postgresql+asyncpg://user:password@localhost/database",
    "AUTH_PEPPER": "p" * 64,
    "JWT_SECRET": "s" * 80,
}


class _RoleRepository:
    def __init__(self, roles: dict[str, Roles]) -> None:
        self.roles = roles
        self.requested_codes: list[str] = []

    async def active_roles_by_code(
        self,
        role_codes: list[str],
    ) -> dict[str, Roles]:
        self.requested_codes = role_codes
        return {
            code: role
            for code, role in self.roles.items()
            if code in role_codes and not role.is_deleted
        }


def _role(*, code: str = "customer", is_deleted: bool = False) -> Roles:
    return Roles(
        id=uuid.uuid4(),
        code=code,
        name=code.replace("_", " ").title(),
        description="Test role",
        is_system=True,
        is_deleted=is_deleted,
    )


def _writer() -> _RegistrationWriter:
    return _RegistrationWriter(
        uow=cast(Any, object()),
        settings=AppSettings(**BASE_SETTINGS),
        passwords=cast(Any, object()),
    )


@pytest.mark.asyncio
async def test_configured_customer_role_is_assigned_successfully() -> None:
    customer = _role()
    repository = _RoleRepository({"customer": customer})

    roles = await _writer()._self_registration_roles(
        repository=cast(Any, repository)
    )

    assert roles == [customer]
    assert repository.requested_codes == ["customer"]


@pytest.mark.asyncio
async def test_missing_or_inactive_default_registration_role_fails_closed() -> None:
    repository = _RoleRepository({})

    with pytest.raises(
        InfrastructureUnavailableError,
        match="Required default role 'customer' is missing",
    ):
        await _writer()._self_registration_roles(
            repository=cast(Any, repository)
        )


@pytest.mark.asyncio
async def test_deleted_default_registration_role_fails_closed() -> None:
    repository = _RoleRepository({"customer": _role(is_deleted=True)})

    with pytest.raises(
        InfrastructureUnavailableError,
        match="Required default role 'customer' is missing",
    ):
        await _writer()._self_registration_roles(
            repository=cast(Any, repository)
        )
