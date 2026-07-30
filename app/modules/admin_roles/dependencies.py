"""Dependency composition for role administration endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.authorization.dependencies import require_permissions
from app.auth.request_context.principals import UserPrincipal
from app.core.di import PostgresUOWDep
from app.modules.admin_roles.service import AdminRolesService

RoleReadPrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.roles.read")),
]
RoleManagePrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.roles.manage")),
]


def get_admin_roles_service(uow: PostgresUOWDep) -> AdminRolesService:
    """Construct the service with FastAPI's request-scoped unit of work."""
    return AdminRolesService(uow=uow)


AdminRolesServiceDep = Annotated[
    AdminRolesService,
    Depends(get_admin_roles_service),
]

__all__ = [
    "AdminRolesServiceDep",
    "RoleManagePrincipal",
    "RoleReadPrincipal",
    "get_admin_roles_service",
]
