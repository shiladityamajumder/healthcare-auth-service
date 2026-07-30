"""File: app/modules/password_management/routes.py
Password recovery, change, and initial-password endpoints."""

from typing import cast

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.auth.identity.canonical import ChannelIdentityPayload, generic_identity
from app.common.response import APIResponse, APIResponseModel
from app.models.enums import OTPPurpose
from app.modules.password_management.dependencies import (
    AuthRateLimitsDep,
    PasswordManagementServiceDep,
    PasswordSensitiveAccess,
    RateLimitRequestContextDep,
    SessionCreationRequestContextDep,
)
from app.modules.password_management.openapi import RESPONSES, TAG
from app.modules.password_management.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    OtpChallengeResponse,
    ResetPasswordProofResponse,
    ResetPasswordWithTokenRequest,
    SetPasswordRequest,
    TokenPairResponse,
    VerifyResetOtpRequest,
)
from app.utils.debug import debug

router = APIRouter(
    prefix="/auth/password",
    tags=[TAG],
    responses=RESPONSES,
)


@router.post(
    "/forgot",
    response_model=APIResponseModel[OtpChallengeResponse],
    summary="Request password reset OTP",
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    context: RateLimitRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: PasswordManagementServiceDep,
) -> JSONResponse:
    """Issue a generic-response password-reset challenge."""
    await rate_limits.password_reset(
        context=context,
        # Pydantic validates these channel-aware fields before this boundary.
        identity=generic_identity(cast(ChannelIdentityPayload, payload)),
    )
    debug("Password reset challenge requested", request_id=context.request_id)
    return APIResponse.success(data=await service.forgot(payload))


@router.post(
    "/reset/verify-otp",
    response_model=APIResponseModel[ResetPasswordProofResponse],
    summary="Verify password reset OTP",
)
async def verify_password_reset_otp(
    payload: VerifyResetOtpRequest,
    context: RateLimitRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: PasswordManagementServiceDep,
) -> JSONResponse:
    """Consume the OTP and return a short-lived one-time reset proof."""
    purpose = (
        OTPPurpose.PASSWORD_RESET_EMAIL.value
        if payload.channel == "email"
        else OTPPurpose.PASSWORD_RESET_PHONE.value
    )
    await rate_limits.otp_verify(
        context=context,
        identity=generic_identity(cast(ChannelIdentityPayload, payload)),
        purpose=purpose,
    )
    result = await service.verify_reset_otp(payload)
    debug("Password reset OTP verified", request_id=context.request_id)
    return APIResponse.success(data=result)


@router.post(
    "/reset",
    response_model=APIResponseModel[TokenPairResponse],
    summary="Reset password using one-time proof",
)
async def reset_password(
    payload: ResetPasswordWithTokenRequest,
    context: SessionCreationRequestContextDep,
    service: PasswordManagementServiceDep,
) -> JSONResponse:
    """Set the new password, revoke existing sessions, and issue a new session."""
    result = await service.reset_with_token(payload, context)
    debug(
        "Password reset completed",
        request_id=context.request_id,
        user_id=str(result.user.id),
    )
    return APIResponse.success(data=result)


@router.put(
    "",
    response_model=APIResponseModel[TokenPairResponse],
    summary="Change authenticated user's password",
)
async def change_password(
    payload: ChangePasswordRequest,
    context: SessionCreationRequestContextDep,
    principal: PasswordSensitiveAccess,
    service: PasswordManagementServiceDep,
) -> JSONResponse:
    """Verify the current password and rotate every active session."""
    return APIResponse.success(
        data=await service.change(
            user_id=principal.user_id,
            payload=payload,
            context=context,
        )
    )


@router.post(
    "",
    response_model=APIResponseModel[TokenPairResponse],
    summary="Set password for an OTP-only account",
)
async def set_password(
    payload: SetPasswordRequest,
    context: SessionCreationRequestContextDep,
    principal: PasswordSensitiveAccess,
    service: PasswordManagementServiceDep,
) -> JSONResponse:
    """Add an initial password to an account that has no password hash."""
    return APIResponse.success(
        data=await service.set(
            user_id=principal.user_id,
            payload=payload,
            context=context,
        )
    )


__all__ = ["router"]
