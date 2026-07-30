"""File: app/modules/login/routes.py
Password and phone-OTP login endpoints."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.auth.identity.canonical import email_identity, phone_identity
from app.common.response import APIResponse, APIResponseModel
from app.models.enums import OTPPurpose
from app.modules.login.dependencies import (
    AuthRateLimitsDep,
    PasswordLoginDep,
    PhoneOtpLoginDep,
    RateLimitRequestContextDep,
    SessionCreationRequestContextDep,
)
from app.modules.login.openapi import RESPONSES, TAG
from app.modules.login.schemas import (
    OtpChallengeResponse,
    PasswordLoginRequest,
    PhoneOtpLoginRequest,
    PhoneOtpLoginVerifyRequest,
    TokenPairResponse,
)
from app.utils.debug import debug

router = APIRouter(prefix="/auth/login", tags=[TAG], responses=RESPONSES)


@router.post(
    "/password",
    response_model=APIResponseModel[TokenPairResponse],
    summary="Login using email or phone and password",
)
async def login_password(
    payload: PasswordLoginRequest,
    context: SessionCreationRequestContextDep,
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
    context: RateLimitRequestContextDep,
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
    context: SessionCreationRequestContextDep,
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
