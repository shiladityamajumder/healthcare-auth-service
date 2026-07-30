"""File: app/modules/current_user/routes.py
Authenticated current-user endpoints."""

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
    UpdateCurrentUserRequest,
    UserPermissionsResponse,
    UserResponse,
    UserRolesResponse,
)

router = APIRouter(
    prefix="/users/me",
    tags=[TAG],
    responses=RESPONSES,
)


@router.get(
    "",
    response_model=APIResponseModel[UserResponse],
    summary="Get current user",
)
async def get_current_user(
    principal: CurrentUserReadAccess,
    service: CurrentUserServiceDep,
) -> JSONResponse:
    """Return authenticated identity details and effective authorization."""
    return APIResponse.success(data=await service.get(user_id=principal.user_id))


@router.patch(
    "",
    response_model=APIResponseModel[UserResponse],
    summary="Update current user preferences",
)
async def update_current_user(
    payload: UpdateCurrentUserRequest,
    principal: CurrentUserWriteAccess,
    service: CurrentUserServiceDep,
) -> JSONResponse:
    """Update locale or timezone without changing login identifiers."""
    return APIResponse.success(
        data=await service.update(user_id=principal.user_id, payload=payload)
    )


@router.get(
    "/roles",
    response_model=APIResponseModel[UserRolesResponse],
    summary="Get current user's roles",
)
async def get_current_user_roles(
    principal: CurrentUserReadAccess,
    service: CurrentUserServiceDep,
) -> JSONResponse:
    """Return effective active role codes."""
    return APIResponse.success(data=await service.roles(user_id=principal.user_id))


@router.get(
    "/permissions",
    response_model=APIResponseModel[UserPermissionsResponse],
    summary="Get current user's permissions",
)
async def get_current_user_permissions(
    principal: CurrentUserReadAccess,
    service: CurrentUserServiceDep,
) -> JSONResponse:
    """Return effective active permission codes."""
    return APIResponse.success(data=await service.permissions(user_id=principal.user_id))


__all__ = ["router"]
