"""File: app/modules/admin_users/routes.py

Purpose:
Defines ``/admin/users`` permission-protected list, detail, status, and global
session-revocation endpoints.

Dependency flow:
HTTP request
-> FastAPI route
-> AdminUserReadAccess or AdminUserManageAccess
-> AdminUsersServiceDep
-> service/repository/unit of work
-> APIResponse
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Path, Query
from fastapi.responses import JSONResponse

from app.common.response import APIResponse, APIResponseModel
from app.core.pagination import PaginationParams
from app.models.enums import UserStatus
from app.modules.admin_users.dependencies import (
    AdminUserManageAccess,
    AdminUserReadAccess,
    AdminUsersServiceDep,
)
from app.modules.admin_users.openapi import RESPONSES, TAG
from app.modules.admin_users.schemas import (
    AdminLogoutAllRequest,
    AdminUserListResponse,
    AdminUserResponse,
    MessageResponse,
    UpdateUserStatusRequest,
)

router = APIRouter(
    prefix="/admin/users",
    tags=[TAG],
    responses=RESPONSES,
)


@router.get(
    "",
    response_model=APIResponseModel[AdminUserListResponse],
    summary="List users",
)
async def list_users(
    principal: AdminUserReadAccess,
    service: AdminUsersServiceDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    search: Annotated[str | None, Query(min_length=2, max_length=320)] = None,
    status_filter: Annotated[UserStatus | None, Query(alias="status")] = None,
) -> JSONResponse:
    """Return a filtered, deterministic page of identities.

    ``AdminUserReadAccess`` authenticates the caller, requires
    ``identity.users.read``, and applies the administrative read limit.
    """
    # Resolution enforces authentication, user-read permission, and rate limiting.
    _ = principal
    data, pagination = await service.list_users(
        pagination=PaginationParams(limit=limit, offset=offset),
        search=search,
        status=status_filter,
    )
    return APIResponse.success(data=data, pagination=pagination)


@router.get(
    "/{userId}",
    response_model=APIResponseModel[AdminUserResponse],
    summary="Get user",
)
async def get_user(
    user_id: Annotated[uuid.UUID, Path(alias="userId")],
    principal: AdminUserReadAccess,
    service: AdminUsersServiceDep,
) -> JSONResponse:
    """Return one identity visible to an authorized administrator.

    Access is protected by ``AdminUserReadAccess`` before the service loads the
    requested user.
    """
    # The service needs only user_id after the dependency secures the request.
    _ = principal
    return APIResponse.success(data=await service.get_user(user_id=user_id))


@router.patch(
    "/{userId}/status",
    response_model=APIResponseModel[AdminUserResponse],
    summary="Update user status",
)
async def update_user_status(
    user_id: Annotated[uuid.UUID, Path(alias="userId")],
    payload: UpdateUserStatusRequest,
    principal: AdminUserManageAccess,
    service: AdminUsersServiceDep,
) -> JSONResponse:
    """Activate, suspend, lock, or close a user account.

    ``AdminUserManageAccess`` enforces manage permission and the admin-write
    limit; the service preserves status-transition invariants.
    """
    return APIResponse.success(
        data=await service.update_status(
            user_id=user_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


@router.post(
    "/{userId}/logout-all",
    response_model=APIResponseModel[MessageResponse],
    summary="Logout user from all devices",
)
async def logout_user_from_all_devices(
    user_id: Annotated[uuid.UUID, Path(alias="userId")],
    payload: AdminLogoutAllRequest,
    principal: AdminUserManageAccess,
    service: AdminUsersServiceDep,
) -> JSONResponse:
    """Administratively revoke every active session for a user.

    The manage access dependency protects this mutation, while the service
    requires the supplied administrative reason.
    """
    return APIResponse.success(
        data=await service.logout_all(
            user_id=user_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


__all__ = ["router"]
