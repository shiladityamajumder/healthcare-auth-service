"""File: app/modules/session_management/dependencies.py

Purpose:
Composes authenticated session read/revocation policies and constructs the
request-scoped session service.

Dependency flow:
FastAPI route parameter
-> SessionReadAccess/SessionRevokeAccess via secure_route()
-> bearer principal and standard/sensitive rate limit
-> PostgresUOWDep
-> SessionManagementServiceDep
"""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.session_management.service import SessionManagementService


def get_session_management_service(
    uow: PostgresUOWDep,
) -> SessionManagementService:
    """Construct the service with FastAPI's request transaction boundary."""
    return SessionManagementService(uow=uow)


# FastAPI constructs the service from the cached request unit of work.
SessionManagementServiceDep = Annotated[
    SessionManagementService,
    Depends(get_session_management_service),
]

# Session inventory resolves a bearer principal and the standard API limit.
SessionReadAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.STANDARD))),
]
# Revocation keeps the same authentication checks with the sensitive limit.
SessionRevokeAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.SENSITIVE))),
]

__all__ = [
    'get_session_management_service',
    'SessionManagementServiceDep',
    'SessionReadAccess',
    'SessionRevokeAccess',
]
