"""Dependency composition for session-management endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import CurrentUserDep
from app.core.di import PostgresUOWDep
from app.modules.session_management.service import SessionManagementService


def get_session_management_service(
    uow: PostgresUOWDep,
) -> SessionManagementService:
    """Construct the service with FastAPI's request transaction boundary."""
    return SessionManagementService(uow=uow)


SessionManagementServiceDep = Annotated[
    SessionManagementService,
    Depends(get_session_management_service),
]

__all__ = [
    "CurrentUserDep",
    "SessionManagementServiceDep",
    "get_session_management_service",
]
