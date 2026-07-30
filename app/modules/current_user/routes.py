"""File: app/modules/current_user/routes.py

Purpose:
Defines ``/users/me`` authenticated profile, preference, role, and permission
endpoints.

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
    """Return authenticated identity details and effective authorization.

    ``CurrentUserReadAccess`` validates the bearer principal/session and applies
    the standard authenticated API limit.
    """
    return APIResponse.success(data=await service.get(user_id=principal.user_id))


@router.patch(
    "",
    response_model=APIResponseModel[UserResponse],
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


@router.get(
    "/roles",
    response_model=APIResponseModel[UserRolesResponse],
    summary="Get current user's roles",
)
async def get_current_user_roles(
    principal: CurrentUserReadAccess,
    service: CurrentUserServiceDep,
) -> JSONResponse:
    """Return effective active role codes for the authenticated caller.

    Current-user read access validates the principal before claims are loaded
    from current database state.
    """
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
    """Return effective active permission codes for the authenticated caller.

    ``CurrentUserReadAccess`` protects and rate-limits this self-service read.
    """
    return APIResponse.success(data=await service.permissions(user_id=principal.user_id))


__all__ = ["router"]
