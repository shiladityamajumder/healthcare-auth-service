"""File: app/modules/session_management/routes.py
User session inventory and revocation endpoints."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.auth.request_context.dependencies import CurrentUserDep
from app.common.response import APIResponse, APIResponseModel
from app.core.di import PostgresUOWDep
from app.modules.session_management.openapi import RESPONSES, TAG
from app.modules.session_management.schemas import MessageResponse, SessionListResponse
from app.modules.session_management.service import SessionManagementService

router = APIRouter(prefix="/auth/sessions", tags=[TAG], responses=RESPONSES)


def get_session_management_service(
    uow: PostgresUOWDep,
) -> SessionManagementService:
    """Build the service with FastAPI's request-scoped unit of work.

    Injecting the transaction boundary avoids hidden sessions and makes
    rollback behavior consistent across every session endpoint.
    """
    return SessionManagementService(uow=uow)


SessionManagementServiceDep = Annotated[
    SessionManagementService,
    Depends(get_session_management_service),
]


@router.get(
    "",
    response_model=APIResponseModel[SessionListResponse],
    summary="List active sessions",
)
async def list_sessions(
    principal: CurrentUserDep,
    service: SessionManagementServiceDep,
) -> JSONResponse:
    """Return active sessions and identify the current session."""
    return APIResponse.success(
        data=await service.list_active(
            user_id=principal.user_id,
            current_session_id=principal.session_id,
        )
    )


@router.delete(
    "/{session_id}",
    response_model=APIResponseModel[MessageResponse],
    summary="Revoke a selected session",
)
async def revoke_session(
    session_id: uuid.UUID,
    principal: CurrentUserDep,
    service: SessionManagementServiceDep,
) -> JSONResponse:
    """Revoke only a session owned by the authenticated user."""
    return APIResponse.success(
        data=await service.revoke(
            user_id=principal.user_id,
            session_id=session_id,
        )
    )


__all__ = ["router"]
