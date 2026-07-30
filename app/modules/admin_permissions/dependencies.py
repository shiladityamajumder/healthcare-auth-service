"""Dependency composition for permission administration endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.admin_permissions.service import AdminPermissionsService

# These aliases make read and mutation security explicit in route signatures.
PermissionReadAccess = Annotated[
    UserPrincipal,
    Depends(
        secure_route(
            RouteSecurityPolicy(
                permissions=frozenset({"identity.permissions.read"}),
                rate_limit=RateLimitPolicy.ADMIN_READ,
            )
        )
    ),
]
PermissionManageAccess = Annotated[
    UserPrincipal,
    Depends(
        secure_route(
            RouteSecurityPolicy(
                permissions=frozenset({"identity.permissions.manage"}),
                rate_limit=RateLimitPolicy.ADMIN_WRITE,
            )
        )
    ),
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
    "PermissionManageAccess",
    "PermissionReadAccess",
    "get_admin_permissions_service",
]
