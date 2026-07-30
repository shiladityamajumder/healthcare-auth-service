"""Dependency composition for email-verification endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import (
    AuthRateLimitsDep,
    AuthRuntimeDep,
    RateLimitRequestContextDep,
    SessionCreationRequestContextDep,
)
from app.core.di import PostgresUOWDep
from app.modules.email_verification.service import EmailVerificationService


def get_email_verification_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> EmailVerificationService:
    """Construct email verification from explicit request dependencies."""
    return EmailVerificationService(
        uow=uow,
        settings=runtime.settings,
        hashing=runtime.hashing,
        tokens=runtime.tokens,
        otp=runtime.otp,
        notifications=runtime.notifications,
    )


EmailVerificationDep = Annotated[
    EmailVerificationService,
    Depends(get_email_verification_service),
]

__all__ = [
    "AuthRateLimitsDep",
    "EmailVerificationDep",
    "RateLimitRequestContextDep",
    "SessionCreationRequestContextDep",
    "get_email_verification_service",
]
