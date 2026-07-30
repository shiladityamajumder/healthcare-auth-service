"""File: app/modules/login/routes.py
Password and phone-OTP login endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.auth.request_context.dependencies import AuthRateLimitsDep, AuthRequestContextDep, AuthRuntimeDep
from app.auth.identity.canonical import email_identity, phone_identity
from app.common.response import APIResponse, APIResponseModel
from app.core.di import PostgresUOWDep
from app.models.enums import OTPPurpose
from app.modules.login.openapi import RESPONSES, TAG
from app.modules.login.schemas import (
    OtpChallengeResponse,
    PasswordLoginRequest,
    PhoneOtpLoginRequest,
    PhoneOtpLoginVerifyRequest,
    TokenPairResponse,
)
from app.modules.login.service import PasswordLoginService, PhoneOtpLoginService
from app.utils.debug import debug

router = APIRouter(prefix="/auth/login", tags=[TAG], responses=RESPONSES)


def get_password_login_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> PasswordLoginService:
    """Build the request-scoped password-login service."""
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
    """Build the request-scoped phone-OTP login service."""
    return PhoneOtpLoginService(
        uow=uow,
        settings=runtime.settings,
        hashing=runtime.hashing,
        tokens=runtime.tokens,
        otp=runtime.otp,
        notifications=runtime.notifications,
    )


PasswordLoginDep = Annotated[
    PasswordLoginService,
    Depends(get_password_login_service),
]
PhoneOtpLoginDep = Annotated[
    PhoneOtpLoginService,
    Depends(get_phone_otp_login_service),
]


@router.post(
    "/password",
    response_model=APIResponseModel[TokenPairResponse],
    summary="Login using email or phone and password",
)
async def login_password(
    payload: PasswordLoginRequest,
    context: AuthRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: PasswordLoginDep,
) -> JSONResponse:
    """Authenticate a password identity and create a device session."""
    if payload.channel == "email":
        assert payload.email is not None
        identity = email_identity(payload.email)
    else:
        assert payload.phone_country_code is not None
        assert payload.phone_number is not None
        identity = phone_identity(payload.phone_country_code, payload.phone_number)
    await rate_limits.login(context=context, identity=identity)
    result = await service.login(payload, context)
    debug(
        "Password login completed",
        request_id=context.request_id,
        user_id=str(result.user.id),
    )
    return APIResponse.success(data=result)


@router.post(
    "/phone/request-otp",
    response_model=APIResponseModel[OtpChallengeResponse],
    summary="Request phone login OTP",
)
async def request_phone_login_otp(
    payload: PhoneOtpLoginRequest,
    context: AuthRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: PhoneOtpLoginDep,
) -> JSONResponse:
    """Issue a login challenge for an existing verified phone identity."""
    identity = phone_identity(payload.phone_country_code, payload.phone_number)
    await rate_limits.otp_request(
        context=context,
        identity=identity,
        purpose=OTPPurpose.LOGIN_PHONE.value,
    )
    debug("Phone login OTP requested", request_id=context.request_id)
    return APIResponse.success(data=await service.request(payload))


@router.post(
    "/phone/verify-otp",
    response_model=APIResponseModel[TokenPairResponse],
    summary="Verify phone login OTP",
)
async def verify_phone_login_otp(
    payload: PhoneOtpLoginVerifyRequest,
    context: AuthRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: PhoneOtpLoginDep,
) -> JSONResponse:
    """Consume a phone login challenge and issue a token pair."""
    identity = phone_identity(payload.phone_country_code, payload.phone_number)
    await rate_limits.otp_verify(
        context=context,
        identity=identity,
        purpose=OTPPurpose.LOGIN_PHONE.value,
    )
    result = await service.verify(payload, context)
    debug(
        "Phone OTP login completed",
        request_id=context.request_id,
        user_id=str(result.user.id),
    )
    return APIResponse.success(data=result)


__all__ = ["router"]
