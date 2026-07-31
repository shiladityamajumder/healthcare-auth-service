"""File: app/modules/current_user/routes.py

Purpose:
Defines current-user profile, preference, and authorization endpoints.

Dependency flow:
HTTP request
-> FastAPI route
-> CurrentUserReadAccess or CurrentUserWriteAccess
-> CurrentUserServiceDep
-> service/repository/unit of work
-> APIResponse
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.common.response import APIResponse, APIResponseModel
from app.modules.current_user.dependencies import (
    CurrentUserReadAccess,
    CurrentUserServiceDep,
    CurrentUserWriteAccess,
)
from app.modules.current_user.openapi import RESPONSES, TAG
from app.modules.current_user.schemas import (
    AuthenticatedUserResponse,
    CurrentAuthorizationResponse,
    UpdateCurrentUserRequest,
)

router = APIRouter(
    prefix="/users/me",
    tags=[TAG],
    responses=RESPONSES,
)

authorization_router = APIRouter(
    prefix="/auth/users/me",
    tags=[TAG],
    responses=RESPONSES,
)


@authorization_router.get(
    "/authorization",
    response_model=APIResponseModel[CurrentAuthorizationResponse],
    summary="Get current authorization",
)
async def get_current_authorization(
    principal: CurrentUserReadAccess,
) -> JSONResponse:
    """Return authorization resolved by the request-scoped principal query."""
    return APIResponse.success(
        data=CurrentAuthorizationResponse(
            roles=sorted(principal.roles),
            permissions=sorted(principal.permissions),
        )
    )


@router.get(
    "",
    response_model=APIResponseModel[AuthenticatedUserResponse],
    summary="Get current user",
)
async def get_current_user(
    principal: CurrentUserReadAccess,
    service: CurrentUserServiceDep,
) -> JSONResponse:
    """Return authenticated identity details without authorization lists.

    ``CurrentUserReadAccess`` validates the bearer principal/session and applies
    the standard authenticated API limit.
    """
    return APIResponse.success(data=await service.get(user_id=principal.user_id))


@router.patch(
    "",
    response_model=APIResponseModel[AuthenticatedUserResponse],
    summary="Update current user profile",
)
async def update_current_user(
    payload: UpdateCurrentUserRequest,
    principal: CurrentUserWriteAccess,
    service: CurrentUserServiceDep,
) -> JSONResponse:
    """Update profile or preferences without changing login identifiers.

    ``CurrentUserWriteAccess`` supplies the authenticated user's identifier and
    applies the sensitive mutation limit.
    """
    return APIResponse.success(
        data=await service.update(user_id=principal.user_id, payload=payload)
    )


__all__ = ["authorization_router", "router"]
