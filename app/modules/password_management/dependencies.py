"""File: app/modules/password_management/dependencies.py

Purpose:
Re-exports public request/rate-limit dependencies, composes sensitive
authenticated access, and constructs the password service.

Dependency flow:
FastAPI route parameter
-> workflow context/rate limit or PasswordSensitiveAccess
-> AuthRuntimeDep and PostgresUOWDep
-> PasswordManagementServiceDep
-> password/OTP/session workflow
"""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import (
    AuthRateLimitsDep,
    AuthRuntimeDep,
    RateLimitRequestContextDep,
    SessionCreationRequestContextDep,
)
from app.auth.request_context.principals import UserPrincipal
from app.auth.route_security import secure_route
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.core.di import PostgresUOWDep
from app.modules.password_management.service import PasswordManagementService


def get_password_management_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> PasswordManagementService:
    """Construct password workflows from explicit request dependencies."""
    return PasswordManagementService(
        uow=uow,
        settings=runtime.settings,
        passwords=runtime.passwords,
        hashing=runtime.hashing,
        tokens=runtime.tokens,
        otp=runtime.otp,
        notifications=runtime.notifications,
    )


# FastAPI constructs one password service from the cached unit of work and
# process-wide password, OTP, token, hashing, and notification primitives.
PasswordManagementServiceDep = Annotated[
    PasswordManagementService,
    Depends(get_password_management_service),
]

# Resolves the bearer principal/session and sensitive API limit for change/set
# operations; recovery routes use workflow-specific public limits instead.
PasswordSensitiveAccess = Annotated[
    UserPrincipal,
    Depends(secure_route(RouteSecurityPolicy(rate_limit=RateLimitPolicy.SENSITIVE))),
]

__all__ = [
    "AuthRateLimitsDep",
    "PasswordManagementServiceDep",
    "PasswordSensitiveAccess",
    "RateLimitRequestContextDep",
    "SessionCreationRequestContextDep",
    "get_password_management_service",
]
