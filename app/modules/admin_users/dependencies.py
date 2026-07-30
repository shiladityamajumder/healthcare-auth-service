"""File: app/modules/admin_users/dependencies.py

Purpose:
Composes administrative user access policies and constructs the request-scoped
application service.

Dependency flow:
FastAPI route parameter
-> AdminUserReadAccess/AdminUserManageAccess via secure_route()
-> bearer principal, permission, and rate-limit validation
-> PostgresUOWDep
-> AdminUsersServiceDep
"""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.admin_users.service import AdminUsersService

# Resolves a bearer principal, requires user-read permission, and applies the
# admin-read rate limit for each request.
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
# Resolves the same principal chain with user-manage permission and the stricter
# admin-write rate limit.
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


# FastAPI builds one service from the cached request-scoped unit of work.
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
