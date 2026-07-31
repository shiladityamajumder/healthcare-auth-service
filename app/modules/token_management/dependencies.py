"""File: app/modules/token_management/dependencies.py

Purpose:
Re-exports token/request-context dependencies, composes authenticated logout
access, and constructs the request-scoped token service.

Dependency flow:
FastAPI route parameter
-> AuthRuntime/context/rate-limit or LogoutAccess dependency
-> PostgresUOWDep
-> TokenManagementServiceDep
-> token/session workflow
"""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import (
    AuthRateLimitsDep,
    AuthRuntimeDep,
    RateLimitRequestContextDep,
    RefreshRequestContextDep,
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


# FastAPI constructs the service from runtime cryptography and the cached
# request-scoped unit of work.
TokenManagementServiceDep = Annotated[
    TokenManagementService,
    Depends(get_token_management_service),
]

# Resolves a bearer principal and sensitive API limit for current-user logout
# mutations; refresh-token logout uses its separate workflow-specific limit.
LogoutAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.SENSITIVE))),
]

__all__ = [
    "AuthRateLimitsDep",
    "LogoutAccess",
    "RateLimitRequestContextDep",
    "RefreshRequestContextDep",
    "TokenManagementServiceDep",
    "TokenManagerDep",
    "get_token_management_service",
]
