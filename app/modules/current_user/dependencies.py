"""Dependency composition for authenticated current-user endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.current_user.service import CurrentUserService


def get_current_user_service(uow: PostgresUOWDep) -> CurrentUserService:
    """Construct the service with FastAPI's request-scoped unit of work.

    FastAPI caches dependencies within one request, so every consumer shares
    the same transaction boundary and unfinished work is rolled back centrally.
    """
    return CurrentUserService(uow=uow)


CurrentUserServiceDep = Annotated[
    CurrentUserService,
    Depends(get_current_user_service),
]

# Profile mutations receive a tighter budget than ordinary account reads.
CurrentUserReadAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.STANDARD))),
]
CurrentUserWriteAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.SENSITIVE))),
]

__all__ = [
    "CurrentUserReadAccess",
    "CurrentUserServiceDep",
    "CurrentUserWriteAccess",
    "get_current_user_service",
]
