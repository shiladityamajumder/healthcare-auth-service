"""Dependency composition for administrative user endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.authorization.dependencies import require_permissions
from app.auth.request_context.principals import UserPrincipal
from app.core.di import PostgresUOWDep
from app.modules.admin_users.service import AdminUsersService

AdminReadPrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.users.read")),
]
AdminManagePrincipal = Annotated[
    UserPrincipal,
    Depends(require_permissions("identity.users.manage")),
]


def get_admin_users_service(uow: PostgresUOWDep) -> AdminUsersService:
    """Construct the service with FastAPI's request-scoped unit of work."""
    return AdminUsersService(uow=uow)


AdminUsersServiceDep = Annotated[
    AdminUsersService,
    Depends(get_admin_users_service),
]

__all__ = [
    "AdminManagePrincipal",
    "AdminReadPrincipal",
    "AdminUsersServiceDep",
    "get_admin_users_service",
]
