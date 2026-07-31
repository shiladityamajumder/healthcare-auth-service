"""File: app/modules/session_management/service.py

Purpose:
Owns authenticated session inventory and ownership-safe targeted revocation.

Dependency flow:
SessionManagementServiceDep and UserPrincipal identifiers
-> request-scoped SQLAlchemyUnitOfWork
-> SessionManagementRepository on the shared session
-> ownership check and optional revocation mutation
-> unit-of-work commit/rollback
-> response contract
"""

from __future__ import annotations

import uuid

from app.common.exceptions import NotFoundError
from app.core.logging import get_logger
from app.db.uow import SQLAlchemyUnitOfWork
from app.modules.session_management.repositories import SessionManagementRepository
from app.modules.session_management.schemas import (
    MessageResponse,
    SessionListResponse,
    SessionResponse,
)
from app.utils.datetime_utils import utc_now

logger = get_logger(__name__)


class SessionManagementService:
    """List and revoke sessions owned by the authenticated user."""

    def __init__(self, *, uow: SQLAlchemyUnitOfWork) -> None:
        self._uow = uow

    async def list_active(
        self,
        *,
        user_id: uuid.UUID,
        current_session_id: uuid.UUID,
    ) -> SessionListResponse:
        """List active visible to the current workflow."""
        async with self._uow:
            records = await SessionManagementRepository(self._uow.session).list_active(
                user_id=user_id, now=utc_now()
            )
            return SessionListResponse(
                sessions=[
                    SessionResponse(
                        id=item.id,
                        device_id=item.device_id,
                        device_type=item.device_type,
                        ip_address=str(item.ip_address) if item.ip_address else None,
                        user_agent=item.user_agent,
                        created_at=item.created_at,
                        last_seen_at=item.last_seen_at,
                        expires_at=item.expires_at,
                        current=item.id == current_session_id,
                    )
                    for item in records
                ]
            )

    async def revoke(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> MessageResponse:
        """Revoke one non-current session owned by the authenticated user."""
        session_revoked = False
        async with self._uow:
            session = await SessionManagementRepository(self._uow.session).get_for_update(
                session_id
            )
            if session is None or session.user_id != user_id:
                raise NotFoundError("The session was not found.")
            if session.revoked_at is None:
                session.revoked_at = utc_now()
                session.revoke_reason = "user_revoked_session"
                session_revoked = True
        logger.info(
            "Security audit event",
            extra={
                "event": "session_revoked",
                "user_id": str(user_id),
                "session_id": str(session_id),
                "session_revoked": session_revoked,
            },
        )
        return MessageResponse(message="The session has been revoked.")


__all__ = ["SessionManagementService"]
