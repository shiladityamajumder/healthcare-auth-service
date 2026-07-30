"""Dependency composition for permission administration endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.authorization.dependencies import require_permissions
from app.auth.request_context.principals import UserPrincipal
from app.core.di import PostgresUOWDep
from app.modules.admin_permissions.service import AdminPermissionsService

PermissionReadPrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.permissions.read")),
]
PermissionManagePrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.permissions.manage")),
]


def get_admin_permissions_service(uow: PostgresUOWDep) -> AdminPermissionsService:
    """Construct the service with FastAPI's request-scoped unit of work.

    Constructor injection keeps transaction ownership explicit and allows
    tests to replace the database boundary without changing route code.
    """
    return AdminPermissionsService(uow=uow)


AdminPermissionsServiceDep = Annotated[
    AdminPermissionsService,
    Depends(get_admin_permissions_service),
]

__all__ = [
    "AdminPermissionsServiceDep",
    "PermissionManagePrincipal",
    "PermissionReadPrincipal",
    "get_admin_permissions_service",
]
