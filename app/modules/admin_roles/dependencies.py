"""Dependency composition for role administration endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.admin_roles.service import AdminRolesService

# Reads and writes use separate permissions and risk-based limiter budgets.
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
