"""File: app/modules/admin_roles/routes.py

Purpose:
Defines ``/admin/roles`` permission-protected RBAC role CRUD endpoints.

Dependency flow:
HTTP request
-> FastAPI route
-> RoleReadAccess or RoleManageAccess
-> AdminRolesServiceDep
-> service/repository/unit of work
-> APIResponse
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse

from app.common.response import APIResponse, APIResponseModel
from app.modules.admin_roles.dependencies import (
    AdminRolesServiceDep,
    RoleManageAccess,
    RoleReadAccess,
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
    principal: RoleReadAccess,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Return all active RBAC roles.

    ``RoleReadAccess`` authenticates the caller and enforces role-read
    permission plus the administrative read limit.
    """
    # Resolution enforces authentication, role-read permission, and rate limiting.
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
    principal: RoleManageAccess,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Create a non-system RBAC role.

    ``RoleManageAccess`` protects the mutation; the service rejects duplicate
    active role codes.
    """
    result = await service.create(payload=payload, actor_user_id=principal.user_id)
    return APIResponse.success(data=result, status_code=status.HTTP_201_CREATED)


@router.get(
    "/{roleId}",
    response_model=APIResponseModel[RoleResponse],
    summary="Get role",
)
async def get_role(
    role_id: Annotated[uuid.UUID, Path(alias="roleId")],
    principal: RoleReadAccess,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Return one active role protected by ``RoleReadAccess``."""
    # The dependency secures this read even though the service needs only role_id.
    _ = principal
    return APIResponse.success(data=await service.get(role_id=role_id))


@router.patch(
    "/{roleId}",
    response_model=APIResponseModel[RoleResponse],
    summary="Update role",
)
async def update_role(
    role_id: Annotated[uuid.UUID, Path(alias="roleId")],
    payload: UpdateRoleRequest,
    principal: RoleManageAccess,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Update a role while preserving system-role invariants.

    The manage dependency protects the route and the service prevents forbidden
    changes to system-owned roles.
    """
    return APIResponse.success(
        data=await service.update(
            role_id=role_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


@router.delete(
    "/{roleId}",
    response_model=APIResponseModel[MessageResponse],
    summary="Delete role",
)
async def delete_role(
    role_id: Annotated[uuid.UUID, Path(alias="roleId")],
    principal: RoleManageAccess,
    service: AdminRolesServiceDep,
) -> JSONResponse:
    """Soft-delete a custom role.

    ``RoleManageAccess`` authorizes the caller; system roles remain protected
    by the service invariant.
    """
    return APIResponse.success(
        data=await service.delete(
            role_id=role_id,
            actor_user_id=principal.user_id,
        )
    )


__all__ = ["router"]
