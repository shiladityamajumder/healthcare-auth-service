"""File: app/modules/session_management/routes.py
User session inventory and revocation endpoints."""

import uuid

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.common.response import APIResponse, APIResponseModel
from app.modules.session_management.dependencies import (
    CurrentUserDep,
    SessionManagementServiceDep,
)
from app.modules.session_management.openapi import RESPONSES, TAG
from app.modules.session_management.schemas import MessageResponse, SessionListResponse

router = APIRouter(prefix="/auth/sessions", tags=[TAG], responses=RESPONSES)


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
