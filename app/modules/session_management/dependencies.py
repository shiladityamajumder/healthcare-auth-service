"""Dependency composition for session-management endpoints."""

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


SessionManagementServiceDep = Annotated[
    SessionManagementService,
    Depends(get_session_management_service),
]

# Revocation writes are more tightly limited than session-list reads.
SessionReadAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.STANDARD))),
]
SessionRevokeAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.SENSITIVE))),
]

__all__ = [
    "SessionManagementServiceDep",
    "SessionReadAccess",
    "SessionRevokeAccess",
    "get_session_management_service",
]
