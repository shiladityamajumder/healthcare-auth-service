"""File: app/modules/login/dependencies.py

Purpose:
Re-exports public login context/rate-limit dependencies and constructs password
and phone-OTP login services.

Dependency flow:
FastAPI route parameter
-> RateLimitRequestContext or SessionCreationRequestContext
-> AuthRuntimeDep and PostgresUOWDep
-> PasswordLoginDep or PhoneOtpLoginDep
-> credential/OTP and session workflow
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
from app.modules.login.service import PasswordLoginService, PhoneOtpLoginService


def get_password_login_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> PasswordLoginService:
    """Construct password login from explicit request dependencies."""
    return PasswordLoginService(
        uow=uow,
        settings=runtime.settings,
        passwords=runtime.passwords,
        hashing=runtime.hashing,
        tokens=runtime.tokens,
    )


def get_phone_otp_login_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> PhoneOtpLoginService:
    """Construct phone-OTP login from the shared authentication runtime."""
    return PhoneOtpLoginService(
        uow=uow,
        settings=runtime.settings,
        hashing=runtime.hashing,
        tokens=runtime.tokens,
        otp=runtime.otp,
        notifications=runtime.notifications,
    )


# FastAPI builds the password service from the cached unit of work and shared
# password/token/authentication runtime primitives.
PasswordLoginDep = Annotated[
    PasswordLoginService,
    Depends(get_password_login_service),
]
# The phone service shares the same request transaction and receives OTP plus
# notification components from AuthRuntime.
PhoneOtpLoginDep = Annotated[
    PhoneOtpLoginService,
    Depends(get_phone_otp_login_service),
]

__all__ = [
    'AuthRateLimitsDep',
    'get_password_login_service',
    'get_phone_otp_login_service',
    'PasswordLoginDep',
    'PhoneOtpLoginDep',
    'RateLimitRequestContextDep',
    'SessionCreationRequestContextDep',
]
