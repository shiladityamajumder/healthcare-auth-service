"""Permission-protected administrative user endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from app.auth.authorization.dependencies import require_permissions
from app.auth.request_context.principals import UserPrincipal
from app.common.response import APIResponse, APIResponseModel
from app.core.di import PostgresUOWDep
from app.core.pagination import PaginationParams
from app.models.enums import UserStatus
from app.modules.admin_users.openapi import RESPONSES, TAG
from app.modules.admin_users.schemas import (
    AdminLogoutAllRequest,
    AdminUserListResponse,
    MessageResponse,
    UpdateUserStatusRequest,
    UserResponse,
)
from app.modules.admin_users.service import AdminUsersService

router = APIRouter(
    prefix="/admin/users",
    tags=[TAG],
    responses=RESPONSES,
)
AdminReadPrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.users.read")),
]
AdminManagePrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.users.manage")),
]


def get_admin_users_service(uow: PostgresUOWDep) -> AdminUsersService:
    """Build the request-scoped administrative user service."""
    return AdminUsersService(uow=uow)


AdminUsersServiceDep = Annotated[
    AdminUsersService,
    Depends(get_admin_users_service),
]


@router.get(
    "",
    response_model=APIResponseModel[AdminUserListResponse],
    summary="List users",
)
async def list_users(
    principal: AdminReadPrincipal,
    service: AdminUsersServiceDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    search: Annotated[str | None, Query(min_length=2, max_length=320)] = None,
    status_filter: Annotated[UserStatus | None, Query(alias="status")] = None,
) -> JSONResponse:
    """Return a filtered, deterministic page of identities."""
    _ = principal
    data, pagination = await service.list_users(
        pagination=PaginationParams(limit=limit, offset=offset),
        search=search,
        status=status_filter,
    )
    return APIResponse.success(data=data, pagination=pagination)


@router.get(
    "/{user_id}",
    response_model=APIResponseModel[UserResponse],
    summary="Get user",
)
async def get_user(
    user_id: uuid.UUID,
    principal: AdminReadPrincipal,
    service: AdminUsersServiceDep,
) -> JSONResponse:
    """Return one identity visible to an authorized administrator."""
    _ = principal
    return APIResponse.success(data=await service.get_user(user_id=user_id))


@router.patch(
    "/{user_id}/status",
    response_model=APIResponseModel[UserResponse],
    summary="Update user status",
)
async def update_user_status(
    user_id: uuid.UUID,
    payload: UpdateUserStatusRequest,
    principal: AdminManagePrincipal,
    service: AdminUsersServiceDep,
) -> JSONResponse:
    """Activate, suspend, lock, or close a user account."""
    return APIResponse.success(
        data=await service.update_status(
            user_id=user_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


@router.post(
    "/{user_id}/logout-all",
    response_model=APIResponseModel[MessageResponse],
    summary="Logout user from all devices",
)
async def logout_user_from_all_devices(
    user_id: uuid.UUID,
    payload: AdminLogoutAllRequest,
    principal: AdminManagePrincipal,
    service: AdminUsersServiceDep,
) -> JSONResponse:
    """Administratively revoke every active session for a user."""
    return APIResponse.success(
        data=await service.logout_all(
            user_id=user_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


__all__ = ["router"]
