"""Dependency composition for administrative user-role endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.admin_user_roles.service import AdminUserRolesService

# Assignment reads and mutations intentionally have different access policies.
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


AdminUserRolesServiceDep = Annotated[
    AdminUserRolesService,
    Depends(get_admin_user_roles_service),
]

__all__ = [
    "AdminUserRolesServiceDep",
    "UserRoleManageAccess",
    "UserRoleReadAccess",
    "get_admin_user_roles_service",
]
