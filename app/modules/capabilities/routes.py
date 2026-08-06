"""Anonymous client-safe authentication capabilities endpoint."""

from __future__ import annotations

import hashlib

from app.auth.request_context.dependencies import AuthRuntimeDep
from app.common.response import APIResponse, APIResponseModel
from app.modules.capabilities.schemas import (
    AuthCapabilitiesResponse,
    LoginCapabilities,
    PasswordPolicyCapabilities,
    RegistrationCapabilities,
    VerificationCapabilities,
)
from fastapi import APIRouter, Header, Response, status
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get(
    "/capabilities",
    response_model=APIResponseModel[AuthCapabilitiesResponse],
    summary="Get public authentication capabilities",
)
async def get_auth_capabilities(
    runtime: AuthRuntimeDep,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
) -> Response:
    """Return cacheable client configuration without security policy data."""
    data = AuthCapabilitiesResponse(
        registration=RegistrationCapabilities(
            email_enabled=True,
            phone_enabled=True,
        ),
        login=LoginCapabilities(
            password_enabled=True,
            phone_otp_enabled=True,
        ),
        verification=VerificationCapabilities(
            email_required=runtime.settings.EMAIL_VERIFICATION_REQUIRED,
            phone_required=runtime.settings.PHONE_VERIFICATION_REQUIRED,
        ),
        password_policy=PasswordPolicyCapabilities(
            minimum_length=runtime.settings.PASSWORD_MIN_LENGTH,
            minimum_character_classes=3,
        ),
        supported_platforms=["android", "ios", "web"],
    )
    digest = hashlib.sha256(data.model_dump_json(by_alias=True).encode("utf-8")).hexdigest()
    etag = f'"{digest}"'
    cache_headers = {
        "Cache-Control": "public, max-age=300",
        "ETag": etag,
    }
    if if_none_match == etag:
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers=cache_headers,
        )
    response: JSONResponse = APIResponse.success(data=data)
    response.headers.update(cache_headers)
    return response


__all__ = ["router"]
