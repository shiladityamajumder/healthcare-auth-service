"""File: tests/unit/test_uow.py

Purpose:
Verifies request-scoped unit-of-work commit and rollback ownership.

Dependency flow:
Fake AsyncSession transaction
-> SQLAlchemyUnitOfWork context
-> success/failure/commit-failure path
-> commit and rollback assertions
"""

from __future__ import annotations

import pytest

from app.db.uow import SQLAlchemyUnitOfWork


class FakeTransaction:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.committed = False
        self.rolled_back = False
        self.fail_commit = fail_commit

    async def commit(self) -> None:
        if self.fail_commit:
            raise RuntimeError("commit failed")
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True


class FakeSession:
    def __init__(self, *, fail_commit: bool = False) -> None:
        self.transaction = FakeTransaction(fail_commit=fail_commit)
        self.session_rollback_called = False
        self.flush_called = False

    def in_transaction(self) -> bool:
        return False

    async def begin(self) -> FakeTransaction:
        return self.transaction

    async def rollback(self) -> None:
        self.session_rollback_called = True

    async def flush(self) -> None:
        self.flush_called = True

    async def refresh(self, instance: object) -> None:
        _ = instance


@pytest.mark.asyncio
async def test_uow_commits_successful_transaction() -> None:
    session = FakeSession()
    uow = SQLAlchemyUnitOfWork(session)  # type: ignore[arg-type]

    async with uow:
        await uow.flush()

    assert session.transaction.committed is True
    assert session.transaction.rolled_back is False
    assert session.flush_called is True
    assert uow.is_active is False


@pytest.mark.asyncio
async def test_uow_rolls_back_when_workflow_raises() -> None:
    session = FakeSession()
    uow = SQLAlchemyUnitOfWork(session)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="workflow failed"):
        async with uow:
            raise ValueError("workflow failed")

    assert session.transaction.committed is False
    assert session.transaction.rolled_back is True
    assert uow.is_active is False


@pytest.mark.asyncio
async def test_uow_rolls_back_session_when_commit_fails() -> None:
    session = FakeSession(fail_commit=True)
    uow = SQLAlchemyUnitOfWork(session)  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="commit failed"):
        async with uow:
            pass

    assert session.session_rollback_called is True
    assert uow.is_active is False
