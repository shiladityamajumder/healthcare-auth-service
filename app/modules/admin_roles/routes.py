"""File: app/modules/admin_roles/routes.py
Permission-protected RBAC role endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.common.response import APIResponse, APIResponseModel
from app.modules.admin_roles.dependencies import (
    AdminRolesServiceDep,
    RoleManagePrincipal,
    RoleReadPrincipal,
)
from app.modules.admin_roles.openapi import RESPONSES, TAG
from app.modules.admin_roles.schemas import (
    CreateRoleRequest,
    MessageResponse,
    RoleListResponse,
    RoleResponse,
    UpdateRoleRequest,
)

router = APIRouter(
    prefix="/admin/roles",
    tags=[TAG],
    responses=RESPONSES,
)


@router.get(
    "",
    response_model=APIResponseModel[RoleListResponse],
    summary="List roles",
)
async def list_roles(
    principal: RoleReadPrincipal,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Return all active RBAC roles."""
    _ = principal
    return APIResponse.success(data=await service.list_roles())


@router.post(
    "",
    response_model=APIResponseModel[RoleResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create role",
)
async def create_role(
    payload: CreateRoleRequest,
    principal: RoleManagePrincipal,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Create a non-system RBAC role."""
    result = await service.create(payload=payload, actor_user_id=principal.user_id)
    return APIResponse.success(data=result, status_code=status.HTTP_201_CREATED)


@router.get(
    "/{role_id}",
    response_model=APIResponseModel[RoleResponse],
    summary="Get role",
)
async def get_role(
    role_id: uuid.UUID,
    principal: RoleReadPrincipal,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Return one active role."""
    _ = principal
    return APIResponse.success(data=await service.get(role_id=role_id))


@router.patch(
    "/{role_id}",
    response_model=APIResponseModel[RoleResponse],
    summary="Update role",
)
async def update_role(
    role_id: uuid.UUID,
    payload: UpdateRoleRequest,
    principal: RoleManagePrincipal,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Update a role while preserving system-role invariants."""
    return APIResponse.success(
        data=await service.update(
            role_id=role_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


@router.delete(
    "/{role_id}",
    response_model=APIResponseModel[MessageResponse],
    summary="Delete role",
)
async def delete_role(
    role_id: uuid.UUID,
    principal: RoleManagePrincipal,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Soft-delete a custom role."""
    return APIResponse.success(
        data=await service.delete(
            role_id=role_id,
            actor_user_id=principal.user_id,
        )
    )


__all__ = ["router"]
