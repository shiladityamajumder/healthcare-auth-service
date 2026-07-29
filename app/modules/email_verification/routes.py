"""Email verification HTTP endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.auth.request_context.dependencies import AuthRateLimitsDep, AuthRequestContextDep, AuthRuntimeDep
from app.auth.identity.canonical import email_identity
from app.common.response import APIResponse, APIResponseModel
from app.core.di import PostgresUOWDep
from app.models.enums import OTPPurpose
from app.modules.email_verification.openapi import RESPONSES, TAG
from app.modules.email_verification.service import EmailVerificationService
from app.modules.email_verification.schemas import (
    EmailVerificationConfirmRequest,
    EmailVerificationRequest,
    OtpChallengeResponse,
    TokenPairResponse,
)
from app.utils.debug import debug

router = APIRouter(
    prefix="/auth/email-verification",
    tags=[TAG],
    responses=RESPONSES,
)


def get_email_verification_service(
    uow: PostgresUOWDep,
    runtime: AuthRuntimeDep,
) -> EmailVerificationService:
    """Build the request-scoped email-verification service."""
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


@router.post(
    "/request",
    response_model=APIResponseModel[OtpChallengeResponse],
    summary="Request email verification OTP",
)
async def request_email_verification(
    payload: EmailVerificationRequest,
    context: AuthRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: EmailVerificationDep,
) -> JSONResponse:
    """Issue or resend an email-verification challenge."""
    await rate_limits.otp_request(
        context=context,
        identity=email_identity(payload.email),
        purpose=OTPPurpose.VERIFY_EMAIL.value,
    )
    debug("Email verification OTP requested", request_id=context.request_id)
    return APIResponse.success(data=await service.request(payload))


@router.post(
    "/verify",
    response_model=APIResponseModel[TokenPairResponse],
    summary="Verify email and issue a session",
)
async def verify_email(
    payload: EmailVerificationConfirmRequest,
    context: AuthRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: EmailVerificationDep,
) -> JSONResponse:
    """Consume the email OTP and activate the verified identity."""
    await rate_limits.otp_verify(
        context=context,
        identity=email_identity(payload.email),
        purpose=OTPPurpose.VERIFY_EMAIL.value,
    )
    result = await service.confirm(payload, context)
    debug(
        "Email verification completed",
        request_id=context.request_id,
        user_id=str(result.user.id),
    )
    return APIResponse.success(data=result)


__all__ = ["router"]
