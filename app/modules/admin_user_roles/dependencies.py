"""File: app/modules/admin_user_roles/dependencies.py

Purpose:
Composes user-role assignment access policies and constructs the request-scoped
assignment service.

Dependency flow:
FastAPI route parameter
-> UserRoleReadAccess/UserRoleManageAccess via secure_route()
-> bearer principal, permission, and rate-limit validation
-> PostgresUOWDep
-> AdminUserRolesServiceDep
"""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.admin_user_roles.service import AdminUserRolesService

# Resolves the principal, user-role read claim, and admin-read limiter policy.
UserRoleReadAccess = Annotated[
    UserPrincipal,
    Depends(
        secure_route(
            RouteSecurityPolicy(
                permissions=frozenset({"identity.user_roles.read"}),
                rate_limit=RateLimitPolicy.ADMIN_READ,
            )
        )
    ),
]
# Assignment mutations require the separate manage claim and write policy.
UserRoleManageAccess = Annotated[
    UserPrincipal,
    Depends(
        secure_route(
            RouteSecurityPolicy(
                permissions=frozenset({"identity.user_roles.manage"}),
                rate_limit=RateLimitPolicy.ADMIN_WRITE,
            )
        )
    ),
]


def get_admin_user_roles_service(uow: PostgresUOWDep) -> AdminUserRolesService:
    """Construct the service with FastAPI's request-scoped unit of work."""
    return AdminUserRolesService(uow=uow)


# FastAPI builds the assignment service from the cached request unit of work.
AdminUserRolesServiceDep = Annotated[
    AdminUserRolesService,
    Depends(get_admin_user_roles_service),
]

__all__ = [
    'AdminUserRolesServiceDep',
    'get_admin_user_roles_service',
    'UserRoleManageAccess',
    'UserRoleReadAccess',
]
