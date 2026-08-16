"""File: app/modules/admin_permissions/dependencies.py

Purpose:
Composes permission/role-policy access controls and the request-scoped
administration service.

Dependency flow:
FastAPI route parameter
-> PermissionReadAccess/PermissionManageAccess via secure_route()
-> bearer principal, permission, and rate-limit validation
-> PostgresUOWDep
-> AdminPermissionsServiceDep
"""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.admin_permissions.service import AdminPermissionsService

# Resolves the bearer principal, permission-read claim, and admin-read rate
# policy for each protected request.
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
# Permission and mapping mutations use the manage claim and write policy.
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


# FastAPI constructs one service around the cached request unit of work.
AdminPermissionsServiceDep = Annotated[
    AdminPermissionsService,
    Depends(get_admin_permissions_service),
]

__all__ = [
    'AdminPermissionsServiceDep',
    'get_admin_permissions_service',
    'PermissionManageAccess',
    'PermissionReadAccess',
]
