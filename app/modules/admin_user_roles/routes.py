"""Permission-protected user-role assignment endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from app.auth.authorization.dependencies import require_permissions
from app.auth.request_context.principals import UserPrincipal
from app.common.response import APIResponse, APIResponseModel
from app.core.di import PostgresUOWDep
from app.modules.admin_user_roles.openapi import RESPONSES, TAG
from app.modules.admin_user_roles.schemas import (
    AssignUserRoleRequest,
    MessageResponse,
    UpdateUserRoleRequest,
    UserRoleListResponse,
    UserRoleResponse,
)
from app.modules.admin_user_roles.service import AdminUserRolesService

router = APIRouter(
    prefix="/admin/users",
    tags=[TAG],
    responses=RESPONSES,
)
UserRoleReadPrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.user_roles.read")),
]
UserRoleManagePrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.user_roles.manage")),
]


def get_admin_user_roles_service(uow: PostgresUOWDep) -> AdminUserRolesService:
    """Build the request-scoped user-role service."""
    return AdminUserRolesService(uow=uow)


AdminUserRolesServiceDep = Annotated[
    AdminUserRolesService,
    Depends(get_admin_user_roles_service),
]


@router.get(
    "/{user_id}/roles",
    response_model=APIResponseModel[UserRoleListResponse],
    summary="Get user role assignments",
)
async def list_user_roles(
    user_id: uuid.UUID,
    principal: UserRoleReadPrincipal,
    service: AdminUserRolesServiceDep,
) -> JSONResponse:
    """Return global and scoped assignments for one user."""
    _ = principal
    return APIResponse.success(
        data=await service.list_assignments(user_id=user_id)
    )


@router.post(
    "/{user_id}/roles",
    response_model=APIResponseModel[UserRoleResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Assign role to user",
)
async def assign_user_role(
    user_id: uuid.UUID,
    payload: AssignUserRoleRequest,
    principal: UserRoleManagePrincipal,
    service: AdminUserRolesServiceDep,
) -> JSONResponse:
    """Create one global or scoped role assignment."""
    result = await service.assign(
        user_id=user_id,
        payload=payload,
        actor_user_id=principal.user_id,
    )
    return APIResponse.success(data=result, status_code=status.HTTP_201_CREATED)


@router.patch(
    "/{user_id}/roles/{user_role_id}",
    response_model=APIResponseModel[UserRoleResponse],
    summary="Update user role assignment",
)
async def update_user_role(
    user_id: uuid.UUID,
    user_role_id: uuid.UUID,
    payload: UpdateUserRoleRequest,
    principal: UserRoleManagePrincipal,
    service: AdminUserRolesServiceDep,
) -> JSONResponse:
    """Update assignment scope, validity, or active state."""
    return APIResponse.success(
        data=await service.update(
            user_id=user_id,
            assignment_id=user_role_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


@router.delete(
    "/{user_id}/roles/{user_role_id}",
    response_model=APIResponseModel[MessageResponse],
    summary="Remove user role assignment",
)
async def remove_user_role(
    user_id: uuid.UUID,
    user_role_id: uuid.UUID,
    principal: UserRoleManagePrincipal,
    service: AdminUserRolesServiceDep,
) -> JSONResponse:
    """Delete one explicit role assignment."""
    return APIResponse.success(
        data=await service.remove(
            user_id=user_id,
            assignment_id=user_role_id,
            actor_user_id=principal.user_id,
        )
    )


__all__ = ["router"]
