"""Dependency composition for email and phone registration endpoints."""

from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import (
    AuthRateLimitsDep,
    AuthRuntimeDep,
    RateLimitRequestContextDep,
    SessionCreationRequestContextDep,
)
from app.core.di import PostgresUOWDep
from app.modules.registration.service import (
    EmailPasswordRegistrationService,
    PhoneOtpRegistrationService,
)


def get_email_registration_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> EmailPasswordRegistrationService:
    """Construct email registration from explicit request dependencies.

    FastAPI supplies one unit of work and the immutable authentication runtime.
    Constructor injection avoids hidden global state and simplifies testing.
    """
    return EmailPasswordRegistrationService(
        uow=uow,
        settings=runtime.settings,
        passwords=runtime.passwords,
        hashing=runtime.hashing,
        tokens=runtime.tokens,
        otp=runtime.otp,
        notifications=runtime.notifications,
    )


def get_phone_registration_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> PhoneOtpRegistrationService:
    """Construct phone registration from the same dependency graph."""
    return PhoneOtpRegistrationService(
        uow=uow,
        settings=runtime.settings,
        passwords=runtime.passwords,
        hashing=runtime.hashing,
        tokens=runtime.tokens,
        otp=runtime.otp,
        notifications=runtime.notifications,
    )


EmailPasswordRegistrationDep = Annotated[
    EmailPasswordRegistrationService,
    Depends(get_email_registration_service),
]
PhoneOtpRegistrationDep = Annotated[
    PhoneOtpRegistrationService,
    Depends(get_phone_registration_service),
]

__all__ = [
    "AuthRateLimitsDep",
    "EmailPasswordRegistrationDep",
    "PhoneOtpRegistrationDep",
    "RateLimitRequestContextDep",
    "SessionCreationRequestContextDep",
    "get_email_registration_service",
    "get_phone_registration_service",
]
