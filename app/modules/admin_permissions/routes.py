"""File: app/modules/admin_permissions/routes.py
Permission-protected permission and role-policy endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status
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
    """Return all active permission definitions."""
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
    """Create one permission master record."""
    result = await service.create(
        payload=payload,
        actor_user_id=principal.user_id,
    )
    return APIResponse.success(data=result, status_code=status.HTTP_201_CREATED)


@permissions_router.get(
    "/{permission_id}",
    response_model=APIResponseModel[PermissionResponse],
    summary="Get permission",
)
async def get_permission(
    permission_id: uuid.UUID,
    principal: PermissionReadAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Return one active permission master record."""
    _ = principal
    return APIResponse.success(data=await service.get(permission_id=permission_id))


@permissions_router.patch(
    "/{permission_id}",
    response_model=APIResponseModel[PermissionResponse],
    summary="Update permission",
)
async def update_permission(
    permission_id: uuid.UUID,
    payload: UpdatePermissionRequest,
    principal: PermissionManageAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Update selected fields on an active permission."""
    return APIResponse.success(
        data=await service.update(
            permission_id=permission_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


@permissions_router.delete(
    "/{permission_id}",
    response_model=APIResponseModel[MessageResponse],
    summary="Delete permission",
)
async def delete_permission(
    permission_id: uuid.UUID,
    principal: PermissionManageAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Soft-delete one permission master record."""
    return APIResponse.success(
        data=await service.delete(
            permission_id=permission_id,
            actor_user_id=principal.user_id,
        )
    )


@role_permissions_router.get(
    "/{role_id}/permissions",
    response_model=APIResponseModel[RolePermissionsResponse],
    summary="Get role permissions",
)
async def get_role_permissions(
    role_id: uuid.UUID,
    principal: PermissionReadAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Return a role's complete active permission set."""
    _ = principal
    return APIResponse.success(data=await service.role_permissions(role_id=role_id))


@role_permissions_router.put(
    "/{role_id}/permissions",
    response_model=APIResponseModel[RolePermissionsResponse],
    summary="Replace role permissions",
)
async def replace_role_permissions(
    role_id: uuid.UUID,
    payload: ReplaceRolePermissionsRequest,
    principal: PermissionManageAccess,
    service: AdminPermissionsServiceDep,
) -> JSONResponse:
    """Atomically replace every permission mapping for a role."""
    return APIResponse.success(
        data=await service.replace_role_permissions(
            role_id=role_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


__all__ = ["permissions_router", "role_permissions_router"]
