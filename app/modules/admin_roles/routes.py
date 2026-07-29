"""Permission-protected RBAC role endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from app.auth.dependencies import require_permissions
from app.auth.principals import UserPrincipal
from app.common.response import APIResponse, APIResponseModel
from app.core.di import PostgresUOWDep
from app.modules.admin_roles.openapi import RESPONSES, TAG
from app.modules.admin_roles.schemas import (
    CreateRoleRequest,
    MessageResponse,
    RoleListResponse,
    RoleResponse,
    UpdateRoleRequest,
)
from app.modules.admin_roles.service import AdminRolesService

router = APIRouter(
    prefix="/admin/roles",
    tags=[TAG],
    responses=RESPONSES,
)
RoleReadPrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.roles.read")),
]
RoleManagePrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.roles.manage")),
]


def get_admin_roles_service(uow: PostgresUOWDep) -> AdminRolesService:
    """Build the request-scoped role service."""
    return AdminRolesService(uow=uow)


AdminRolesServiceDep = Annotated[
    AdminRolesService,
    Depends(get_admin_roles_service),
]


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
