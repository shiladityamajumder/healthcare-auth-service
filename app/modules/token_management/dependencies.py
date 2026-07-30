"""Dependency composition for token, logout, and JWKS endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import (
    AuthRateLimitsDep,
    AuthRuntimeDep,
    RateLimitRequestContextDep,
    SessionCreationRequestContextDep,
    TokenManagerDep,
)
from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.token_management.service import TokenManagementService


def get_token_management_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> TokenManagementService:
    """Construct token workflows from explicit request dependencies."""
    return TokenManagementService(
        uow=uow,
        hashing=runtime.hashing,
        tokens=runtime.tokens,
    )


TokenManagementServiceDep = Annotated[
    TokenManagementService,
    Depends(get_token_management_service),
]

# Access-token logout operations require authentication and a sensitive budget.
LogoutAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.SENSITIVE))),
]

__all__ = [
    "AuthRateLimitsDep",
    "LogoutAccess",
    "RateLimitRequestContextDep",
    "SessionCreationRequestContextDep",
    "TokenManagementServiceDep",
    "TokenManagerDep",
    "get_token_management_service",
]
