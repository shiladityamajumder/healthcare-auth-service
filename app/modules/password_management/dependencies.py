"""Dependency composition for password lifecycle endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import (
    AuthRateLimitsDep,
    AuthRuntimeDep,
    CurrentUserDep,
    RateLimitRequestContextDep,
    SessionCreationRequestContextDep,
)
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


PasswordManagementServiceDep = Annotated[
    PasswordManagementService,
    Depends(get_password_management_service),
]

__all__ = [
    "AuthRateLimitsDep",
    "CurrentUserDep",
    "PasswordManagementServiceDep",
    "RateLimitRequestContextDep",
    "SessionCreationRequestContextDep",
    "get_password_management_service",
]
