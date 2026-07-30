"""Dependency composition for token, logout, and JWKS endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import (
    AuthRateLimitsDep,
    AuthRuntimeDep,
    CurrentUserDep,
    SessionCreationRequestContextDep,
    TokenManagerDep,
)
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

__all__ = [
    "AuthRateLimitsDep",
    "CurrentUserDep",
    "SessionCreationRequestContextDep",
    "TokenManagementServiceDep",
    "TokenManagerDep",
    "get_token_management_service",
]
