"""File: app/db/uow.py
Request-scoped SQLAlchemy transaction boundary."""

from __future__ import annotations

from time import perf_counter
from types import TracebackType
from typing import Any, Self

from sqlalchemy.ext.asyncio import AsyncSession, AsyncSessionTransaction

from app.core.logging import get_logger

logger = get_logger(__name__)


class SQLAlchemyUnitOfWork:
    """Own one explicit transaction on an externally managed AsyncSession.

    The instance is request scoped and must never be shared between concurrent
    tasks. Repositories are constructed from :attr:`session` inside one
    application-service workflow.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._transaction: AsyncSessionTransaction | None = None
        self._started_at: float | None = None

    @property
    def session(self) -> AsyncSession:
        """Return the session for repository construction only."""
        return self._session

    @property
    def is_active(self) -> bool:
        """Return whether this instance owns an active transaction."""
        return self._transaction is not None

    async def begin(self) -> None:
        """Begin an explicit transaction.

        Raises:
            RuntimeError: If this unit owns a transaction or SQLAlchemy already
                autobegan one on the session. Services must enter the unit of
                work before issuing relational queries for a write workflow.
        """
        if self.is_active:
            raise RuntimeError("This unit of work already owns a transaction")
        if self._session.in_transaction():
            raise RuntimeError(
                "The session already has a transaction. Enter the unit of work "
                "before executing repository operations."
            )
        self._transaction = await self._session.begin()
        self._started_at = perf_counter()
        logger.debug("Database transaction started")

    async def __aenter__(self) -> Self:
        """Begin the transaction and return this unit of work."""
        await self.begin()
        return self

    async def commit(self) -> None:
        """Commit the owned transaction and clear internal state."""
        transaction = self._require_transaction()
        try:
            await transaction.commit()
            logger.debug(
                "Database transaction committed",
                extra={"duration_ms": self._duration_ms()},
            )
        except Exception:
            logger.error("Database transaction commit failed", exc_info=True)
            try:
                await self._session.rollback()
            except Exception:
                logger.error(
                    "Rollback after commit failure also failed",
                    exc_info=True,
                )
            raise
        finally:
            self._clear_state()

    async def rollback(self) -> None:
        """Roll back the owned transaction and clear internal state."""
        transaction = self._require_transaction()
        try:
            await transaction.rollback()
            logger.info(
                "Database transaction rolled back",
                extra={"duration_ms": self._duration_ms()},
            )
        finally:
            self._clear_state()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit success or roll back while preserving the original failure."""
        _ = exc_type, traceback
        if not self.is_active:
            return
        if exc is None:
            await self.commit()
            return
        try:
            await self.rollback()
        except Exception:
            logger.error(
                "Rollback failed while another exception was active",
                extra={"original_exception_type": type(exc).__name__},
                exc_info=True,
            )

    async def flush(self) -> None:
        """Flush pending ORM state without committing."""
        if not self.is_active:
            raise RuntimeError("flush requires an active unit-of-work transaction")
        await self._session.flush()

    async def refresh(self, instance: Any) -> None:
        """Refresh an ORM instance inside the active transaction."""
        if not self.is_active:
            raise RuntimeError("refresh requires an active unit-of-work transaction")
        await self._session.refresh(instance)

    def _require_transaction(self) -> AsyncSessionTransaction:
        if self._transaction is None:
            raise RuntimeError("No unit-of-work transaction is active")
        return self._transaction

    def _duration_ms(self) -> float | None:
        if self._started_at is None:
            return None
        return round((perf_counter() - self._started_at) * 1_000, 2)

    def _clear_state(self) -> None:
        self._transaction = None
        self._started_at = None


__all__ = ["SQLAlchemyUnitOfWork"]
