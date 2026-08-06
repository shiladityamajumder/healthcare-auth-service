"""File: app/modules/admin_user_roles/routes.py

Purpose:
Defines ``/admin/users/{userId}/roles`` permission-protected assignment list,
create, update, and removal endpoints.

Dependency flow:
HTTP request
-> FastAPI route
-> UserRoleReadAccess or UserRoleManageAccess
-> AdminUserRolesServiceDep
-> service/repository/unit of work
-> APIResponse
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse

from app.common.response import APIResponse, APIResponseModel
from app.modules.admin_user_roles.dependencies import (
    AdminUserRolesServiceDep,
    UserRoleManageAccess,
    UserRoleReadAccess,
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
    "/{userId}/roles",
    response_model=APIResponseModel[UserRoleListResponse],
    summary="Get user role assignments",
)
async def list_user_roles(
    user_id: Annotated[uuid.UUID, Path(alias="userId")],
    principal: UserRoleReadAccess,
    service: AdminUserRolesServiceDep,
) -> JSONResponse:
    """Return global and scoped assignments for one user.

    ``UserRoleReadAccess`` enforces authentication, assignment-read permission,
    and the administrative read limit.
    """
    # The dependency protects the read; the service is scoped by target user_id.
    _ = principal
    return APIResponse.success(data=await service.list_assignments(user_id=user_id))


@router.post(
    "/{userId}/roles",
    response_model=APIResponseModel[UserRoleResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Assign role to user",
)
async def assign_user_role(
    user_id: Annotated[uuid.UUID, Path(alias="userId")],
    payload: AssignUserRoleRequest,
    principal: UserRoleManageAccess,
    service: AdminUserRolesServiceDep,
) -> JSONResponse:
    """Create one global or scoped role assignment.

    Manage access protects the mutation; the service validates the target user,
    active role, scope, and validity window.
    """
    result = await service.assign(
        user_id=user_id,
        payload=payload,
        actor_user_id=principal.user_id,
    )
    return APIResponse.success(data=result, status_code=status.HTTP_201_CREATED)


@router.patch(
    "/{userId}/roles/{userRoleId}",
    response_model=APIResponseModel[UserRoleResponse],
    summary="Update user role assignment",
)
async def update_user_role(
    user_id: Annotated[uuid.UUID, Path(alias="userId")],
    user_role_id: Annotated[uuid.UUID, Path(alias="userRoleId")],
    payload: UpdateUserRoleRequest,
    principal: UserRoleManageAccess,
    service: AdminUserRolesServiceDep,
) -> JSONResponse:
    """Update assignment scope, validity, or active state.

    ``UserRoleManageAccess`` protects the route and ownership-filtered repository
    lookup prevents cross-user assignment updates.
    """
    return APIResponse.success(
        data=await service.update(
            user_id=user_id,
            assignment_id=user_role_id,
            payload=payload,
            actor_user_id=principal.user_id,
        )
    )


@router.delete(
    "/{userId}/roles/{userRoleId}",
    response_model=APIResponseModel[MessageResponse],
    summary="Remove user role assignment",
)
async def remove_user_role(
    user_id: Annotated[uuid.UUID, Path(alias="userId")],
    user_role_id: Annotated[uuid.UUID, Path(alias="userRoleId")],
    principal: UserRoleManageAccess,
    service: AdminUserRolesServiceDep,
) -> JSONResponse:
    """Delete one explicit role assignment.

    The manage dependency runs before an ownership-filtered assignment is
    deleted within the unit-of-work transaction.
    """
    return APIResponse.success(
        data=await service.remove(
            user_id=user_id,
            assignment_id=user_role_id,
            actor_user_id=principal.user_id,
        )
    )


__all__ = ["router"]
