"""File: app/modules/admin_user_roles/routes.py
Permission-protected user-role assignment endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.common.response import APIResponse, APIResponseModel
from app.modules.admin_user_roles.dependencies import (
    AdminUserRolesServiceDep,
    UserRoleManagePrincipal,
    UserRoleReadPrincipal,
)
from app.modules.admin_user_roles.openapi import RESPONSES, TAG
from app.modules.admin_user_roles.schemas import (
    AssignUserRoleRequest,
    MessageResponse,
    UpdateUserRoleRequest,
    UserRoleListResponse,
    UserRoleResponse,
)

router = APIRouter(
    prefix="/admin/users",
    tags=[TAG],
    responses=RESPONSES,
)


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
    return APIResponse.success(data=await service.list_assignments(user_id=user_id))


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
