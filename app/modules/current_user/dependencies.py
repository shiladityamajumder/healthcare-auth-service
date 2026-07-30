"""File: app/modules/current_user/dependencies.py

Purpose:
Composes current-user authentication/rate-limit policies and constructs the
request-scoped profile service.

Dependency flow:
FastAPI route parameter
-> CurrentUserReadAccess/CurrentUserWriteAccess via secure_route()
-> bearer principal and standard/sensitive rate limit
-> PostgresUOWDep
-> CurrentUserServiceDep
"""

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


# FastAPI constructs one service around the cached request unit of work.
CurrentUserServiceDep = Annotated[
    CurrentUserService,
    Depends(get_current_user_service),
]

# Resolves the authenticated bearer principal and applies the standard API
# limit; no additional permission claim is required for self-service reads.
CurrentUserReadAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.STANDARD))),
]
# Self-service mutations retain authentication but use the sensitive API tier.
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
