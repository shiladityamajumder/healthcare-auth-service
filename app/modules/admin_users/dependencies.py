"""Dependency composition for administrative user endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.admin_users.service import AdminUsersService

# Route aliases combine bearer authentication, authorization, and rate limiting.
AdminUserReadAccess = Annotated[
    UserPrincipal,
    Depends(
        secure_route(
            RouteSecurityPolicy(
                permissions=frozenset({"identity.users.read"}),
                rate_limit=RateLimitPolicy.ADMIN_READ,
            )
        )
    ),
]
AdminUserManageAccess = Annotated[
    UserPrincipal,
    Depends(
        secure_route(
            RouteSecurityPolicy(
                permissions=frozenset({"identity.users.manage"}),
                rate_limit=RateLimitPolicy.ADMIN_WRITE,
            )
        )
    ),
]


def get_admin_users_service(uow: PostgresUOWDep) -> AdminUsersService:
    """Construct the service with FastAPI's request-scoped unit of work."""
    return AdminUsersService(uow=uow)


AdminUsersServiceDep = Annotated[
    AdminUsersService,
    Depends(get_admin_users_service),
]

__all__ = [
    "AdminUserManageAccess",
    "AdminUserReadAccess",
    "AdminUsersServiceDep",
    "get_admin_users_service",
]
