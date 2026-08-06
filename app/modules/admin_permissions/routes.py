"""File: app/modules/admin_permissions/routes.py

Purpose:
Defines ``/admin/permissions`` CRUD and ``/admin/roles/{roleId}/permissions``
policy endpoints.

Dependency flow:
HTTP request
-> FastAPI route
-> PermissionReadAccess or PermissionManageAccess
-> AdminPermissionsServiceDep
-> service/repository/unit of work
-> APIResponse
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse

from app.common.response import APIResponse, APIResponseModel
from app.modules.admin_permissions.dependencies import (
    AdminPermissionsServiceDep,
    PermissionManageAccess,
    PermissionReadAccess,
)
from app.modules.admin_permissions.openapi import RESPONSES, TAG
from app.modules.admin_permissions.schemas import (
    CreatePermissionRequest,
    MessageResponse,
    PermissionListResponse,
    PermissionResponse,
    ReplaceRolePermissionsRequest,
    RolePermissionsResponse,
    UpdatePermissionRequest,
)

permissions_router = APIRouter(
    prefix="/admin/permissions",
    tags=[TAG],
    responses=RESPONSES,
)
role_permissions_router = APIRouter(
    prefix="/admin/roles",
    tags=[TAG],
    responses=RESPONSES,
)


@permissions_router.get(
    "",
    response_model=APIResponseModel[PermissionListResponse],
    summary="List permissions",
)
async def list_permissions(
    principal: PermissionReadAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Return all active permission definitions.

    ``PermissionReadAccess`` enforces bearer authentication, permission-read
    authorization, and the admin-read rate limit.
    """
    # Resolution enforces authentication, read permission, and rate limiting.
    _ = principal
    return APIResponse.success(data=await service.list_permissions())


@permissions_router.post(
    "",
    response_model=APIResponseModel[PermissionResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create permission",
)
async def create_permission(
    payload: CreatePermissionRequest,
    principal: PermissionManageAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Create one permission master record.

    ``PermissionManageAccess`` protects the mutation and the service preserves
    active permission-code uniqueness.
    """
    result = await service.create(
        payload=payload,
        actor_user_id=principal.user_id,
    )
    return APIResponse.success(data=result, status_code=status.HTTP_201_CREATED)


@permissions_router.get(
    "/{permissionId}",
    response_model=APIResponseModel[PermissionResponse],
    summary="Get permission",
)
async def get_permission(
    permission_id: Annotated[uuid.UUID, Path(alias="permissionId")],
    principal: PermissionReadAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Return one active permission protected by ``PermissionReadAccess``."""
    # The service needs only the resource ID; the dependency already secured access.
    _ = principal
    return APIResponse.success(data=await service.get(permission_id=permission_id))


@permissions_router.patch(
    "/{permissionId}",
    response_model=APIResponseModel[PermissionResponse],
    summary="Update permission",
)
async def update_permission(
    permission_id: Annotated[uuid.UUID, Path(alias="permissionId")],
    payload: UpdatePermissionRequest,
    principal: PermissionManageAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Update selected fields on an active permission.

    The manage access dependency authorizes and rate-limits the request before
    the service applies uniqueness checks.
    """
    return APIResponse.success(
        data=await service.update(
            permission_id=permission_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


@permissions_router.delete(
    "/{permissionId}",
    response_model=APIResponseModel[MessageResponse],
    summary="Delete permission",
)
async def delete_permission(
    permission_id: Annotated[uuid.UUID, Path(alias="permissionId")],
    principal: PermissionManageAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Soft-delete one permission master record.

    ``PermissionManageAccess`` protects this administrative write operation.
    """
    return APIResponse.success(
        data=await service.delete(
            permission_id=permission_id,
            actor_user_id=principal.user_id,
        )
    )


@role_permissions_router.get(
    "/{roleId}/permissions",
    response_model=APIResponseModel[RolePermissionsResponse],
    summary="Get role permissions",
)
async def get_role_permissions(
    role_id: Annotated[uuid.UUID, Path(alias="roleId")],
    principal: PermissionReadAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Return a role's complete active permission set.

    Read access is permission-protected; inactive role or permission records
    are excluded by the repository/service flow.
    """
    # The principal is resolved for route protection, not service input.
    _ = principal
    return APIResponse.success(data=await service.role_permissions(role_id=role_id))


@role_permissions_router.put(
    "/{roleId}/permissions",
    response_model=APIResponseModel[RolePermissionsResponse],
    summary="Replace role permissions",
)
async def replace_role_permissions(
    role_id: Annotated[uuid.UUID, Path(alias="roleId")],
    payload: ReplaceRolePermissionsRequest,
    principal: PermissionManageAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Atomically replace every permission mapping for a role.

    Manage access is enforced before the unit-of-work transaction replaces the
    complete mapping set.
    """
    return APIResponse.success(
        data=await service.replace_role_permissions(
            role_id=role_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


__all__ = ["permissions_router", "role_permissions_router"]
