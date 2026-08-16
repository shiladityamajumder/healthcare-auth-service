"""File: app/modules/registration/dependencies.py

Purpose:
Re-exports public registration context/rate-limit dependencies and constructs
email/password and phone/OTP registration services.

Dependency flow:
FastAPI route parameter
-> RateLimitRequestContext or SessionCreationRequestContext
-> AuthRuntimeDep and PostgresUOWDep
-> EmailPasswordRegistrationDep or PhoneOtpRegistrationDep
-> account/role/OTP/session workflow
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


# FastAPI builds the email service from the cached request unit of work and
# process-wide password, OTP, token, and notification primitives.
EmailPasswordRegistrationDep = Annotated[
    EmailPasswordRegistrationService,
    Depends(get_email_registration_service),
]
# The phone service shares the same transaction/runtime boundaries and verifies
# the one-time challenge before it creates an account.
PhoneOtpRegistrationDep = Annotated[
    PhoneOtpRegistrationService,
    Depends(get_phone_registration_service),
]

__all__ = [
    'AuthRateLimitsDep',
    'EmailPasswordRegistrationDep',
    'get_email_registration_service',
    'get_phone_registration_service',
    'PhoneOtpRegistrationDep',
    'RateLimitRequestContextDep',
    'SessionCreationRequestContextDep',
]
