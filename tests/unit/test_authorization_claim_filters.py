"""Effective-authorization query security filters."""

from __future__ import annotations

import uuid
from typing import Any, cast

import pytest
from app.auth.authorization.claims import load_authorization_claims
from app.utils.datetime_utils import utc_now
from sqlalchemy.dialects import postgresql


class _ScalarResult:
    def __init__(self, values: tuple[str, ...]) -> None:
        self._values = values

    def all(self) -> tuple[str, ...]:
        return self._values


class _CapturingSession:
    def __init__(self) -> None:
        self.statements: list[object] = []

    async def scalars(self, statement: object) -> _ScalarResult:
        self.statements.append(statement)
        if len(self.statements) == 1:
            return _ScalarResult(("customer",))
        return _ScalarResult(("orders.read",))


@pytest.mark.asyncio
async def test_effective_authorization_excludes_inactive_expired_scoped_and_deleted_data() -> None:
    """Keep all assignment and soft-delete filters in the canonical loader."""
    session = _CapturingSession()

    claims = await load_authorization_claims(
        cast(Any, session),
        user_id=uuid.uuid4(),
        now=utc_now(),
    )
    sql = "\n".join(
        str(
            statement.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        ).casefold()
        for statement in session.statements
    )

    assert claims.roles == ("customer",)
    assert claims.permissions == ("orders.read",)
    assert "user_roles.is_active is true" in sql
    assert "user_roles.scope_type is null" in sql
    assert "user_roles.scope_id is null" in sql
    assert "user_roles.valid_from is null" in sql
    assert "user_roles.valid_from <=" in sql
    assert "user_roles.valid_until is null" in sql
    assert "user_roles.valid_until >" in sql
    assert "roles.is_deleted is false" in sql
    assert "permissions.is_deleted is false" in sql
