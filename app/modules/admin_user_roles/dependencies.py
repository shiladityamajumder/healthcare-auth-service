"""Dependency composition for administrative user-role endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.authorization.dependencies import require_permissions
from app.auth.request_context.principals import UserPrincipal
from app.core.di import PostgresUOWDep
from app.modules.admin_user_roles.service import AdminUserRolesService

UserRoleReadPrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.user_roles.read")),
]
UserRoleManagePrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.user_roles.manage")),
]


def get_admin_user_roles_service(uow: PostgresUOWDep) -> AdminUserRolesService:
    """Construct the service with FastAPI's request-scoped unit of work."""
    return AdminUserRolesService(uow=uow)


AdminUserRolesServiceDep = Annotated[
    AdminUserRolesService,
    Depends(get_admin_user_roles_service),
]

__all__ = [
    "AdminUserRolesServiceDep",
    "UserRoleManagePrincipal",
    "UserRoleReadPrincipal",
    "get_admin_user_roles_service",
]
