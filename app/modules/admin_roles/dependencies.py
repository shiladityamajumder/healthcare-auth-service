"""File: app/modules/admin_roles/dependencies.py

Purpose:
Composes RBAC role access policies and the request-scoped role administration
service dependency.

Dependency flow:
FastAPI route parameter
-> RoleReadAccess/RoleManageAccess via secure_route()
-> bearer principal, permission, and rate-limit validation
-> PostgresUOWDep
-> AdminRolesServiceDep
"""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.admin_roles.service import AdminRolesService

# Resolves the authenticated principal, role-read permission, and admin-read
# limiter policy per request.
RoleReadAccess = Annotated[
    UserPrincipal,
    Depends(
        secure_route(
            RouteSecurityPolicy(
                permissions=frozenset({"identity.roles.read"}),
                rate_limit=RateLimitPolicy.ADMIN_READ,
            )
        )
    ),
]
# Role mutations require the independent manage permission and write budget.
RoleManageAccess = Annotated[
    UserPrincipal,
    Depends(
        secure_route(
            RouteSecurityPolicy(
                permissions=frozenset({"identity.roles.manage"}),
                rate_limit=RateLimitPolicy.ADMIN_WRITE,
            )
        )
    ),
]


def get_admin_roles_service(uow: PostgresUOWDep) -> AdminRolesService:
    """Construct the service with FastAPI's request-scoped unit of work."""
    return AdminRolesService(uow=uow)


# FastAPI constructs the service from the cached request unit of work.
AdminRolesServiceDep = Annotated[
    AdminRolesService,
    Depends(get_admin_roles_service),
]

__all__ = [
    "AdminRolesServiceDep",
    "RoleManageAccess",
    "RoleReadAccess",
    "get_admin_roles_service",
]
