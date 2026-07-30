"""File: app/modules/email_verification/dependencies.py

Purpose:
Re-exports narrow request/rate-limit dependencies and constructs the
request-scoped email-verification service.

Dependency flow:
FastAPI route parameter
-> rate-limit or session-creation request context
-> AuthRuntimeDep and PostgresUOWDep
-> EmailVerificationDep
-> OTP/session workflow
"""

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


# FastAPI constructs one verification service from the cached unit of work and
# process-wide authentication primitives.
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
