"""File: app/modules/registration/routes.py
Registration HTTP endpoints."""

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.auth.identity.canonical import email_identity, phone_identity
from app.common.response import APIResponse, APIResponseModel
from app.models.enums import OTPPurpose
from app.modules.registration.dependencies import (
    AuthRateLimitsDep,
    EmailPasswordRegistrationDep,
    PhoneOtpRegistrationDep,
    RateLimitRequestContextDep,
    SessionCreationRequestContextDep,
)
from app.modules.registration.openapi import RESPONSES, TAG
from app.modules.registration.schemas import (
    EmailPasswordRegistrationRequest,
    OtpChallengeResponse,
    PhoneOtpRegistrationRequest,
    PhoneOtpRegistrationVerifyRequest,
    RegistrationResponse,
    TokenPairResponse,
)
from app.utils.debug import debug

router = APIRouter(
    prefix="/auth/register",
    tags=[TAG],
    responses=RESPONSES,
)


@router.post(
    "/email",
    response_model=APIResponseModel[RegistrationResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Register using email and password",
)
async def register_email(
    payload: EmailPasswordRegistrationRequest,
    context: SessionCreationRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: EmailPasswordRegistrationDep,
) -> JSONResponse:
    """Create an email identity with one or more validated initial roles."""
    await rate_limits.registration(
        context=context,
        identity=email_identity(payload.email),
    )
    debug("Email registration accepted", request_id=context.request_id)
    result = await service.register(payload, context)
    return APIResponse.success(data=result, status_code=status.HTTP_201_CREATED)


@router.post(
    "/phone/request-otp",
    response_model=APIResponseModel[OtpChallengeResponse],
    summary="Request phone registration OTP",
)
async def request_phone_registration_otp(
    payload: PhoneOtpRegistrationRequest,
    context: RateLimitRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: PhoneOtpRegistrationDep,
) -> JSONResponse:
    """Issue a bounded phone-registration OTP challenge."""
    identity = phone_identity(payload.phone_country_code, payload.phone_number)
    await rate_limits.otp_request(
        context=context,
        identity=identity,
        purpose=OTPPurpose.REGISTRATION_PHONE.value,
    )
    debug("Phone registration OTP requested", request_id=context.request_id)
    return APIResponse.success(data=await service.request(payload))


@router.post(
    "/phone/verify-otp",
    response_model=APIResponseModel[TokenPairResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Verify phone OTP and create account",
)
async def verify_phone_registration_otp(
    payload: PhoneOtpRegistrationVerifyRequest,
    context: SessionCreationRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: PhoneOtpRegistrationDep,
) -> JSONResponse:
    """Consume a phone OTP and create the user and first session atomically."""
    identity = phone_identity(payload.phone_country_code, payload.phone_number)
    await rate_limits.otp_verify(
        context=context,
        identity=identity,
        purpose=OTPPurpose.REGISTRATION_PHONE.value,
    )
    result = await service.verify(payload, context)
    debug(
        "Phone registration completed",
        request_id=context.request_id,
        user_id=str(result.user.id),
    )
    return APIResponse.success(data=result, status_code=status.HTTP_201_CREATED)


__all__ = ["router"]
