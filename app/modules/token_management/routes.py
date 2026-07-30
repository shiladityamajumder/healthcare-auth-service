"""File: app/modules/token_management/routes.py
Refresh-token rotation, logout, and JWKS endpoints."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.common.exceptions import NotFoundError
from app.common.response import APIResponse, APIResponseModel
from app.modules.token_management.dependencies import (
    AuthRateLimitsDep,
    CurrentUserDep,
    SessionCreationRequestContextDep,
    TokenManagementServiceDep,
    TokenManagerDep,
)
from app.modules.token_management.openapi import RESPONSES, TAG
from app.modules.token_management.schemas import (
    JWKSResponse,
    LogoutRequest,
    MessageResponse,
    RefreshTokenRequest,
    TokenPairResponse,
)
from app.utils.debug import debug

router = APIRouter(prefix="/auth", tags=[TAG], responses=RESPONSES)


@router.get(
    "/.well-known/jwks.json",
    response_model=APIResponseModel[JWKSResponse],
    summary="Publish active JWT verification keys",
)
async def jwks(tokens: TokenManagerDep) -> JSONResponse:
    """Publish public RS256 keys without exposing private key material."""
    keys = tokens.public_jwks()
    if not keys:
        raise NotFoundError("JWKS is available only when RS256 is configured.")
    return APIResponse.success(data=JWKSResponse(keys=keys))


@router.post(
    "/token/refresh",
    response_model=APIResponseModel[TokenPairResponse],
    summary="Rotate a refresh token",
)
async def refresh_token(
    payload: RefreshTokenRequest,
    context: SessionCreationRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: TokenManagementServiceDep,
) -> JSONResponse:
    """Rotate the refresh token and reject token-family reuse."""
    await rate_limits.refresh(
        context=context,
        token_fingerprint=payload.refresh_token[-32:],
    )
    result = await service.refresh(payload, context)
    debug(
        "Refresh token rotated",
        request_id=context.request_id,
        user_id=str(result.user.id),
    )
    return APIResponse.success(data=result)


@router.post(
    "/logout",
    response_model=APIResponseModel[MessageResponse],
    summary="Logout the refresh-token session",
)
async def logout(
    payload: LogoutRequest,
    service: TokenManagementServiceDep,
) -> JSONResponse:
    """Revoke the session identified by a valid refresh token."""
    return APIResponse.success(data=await service.logout(payload))


@router.post(
    "/logout/others",
    response_model=APIResponseModel[MessageResponse],
    summary="Logout from every other device",
)
async def logout_others(
    principal: CurrentUserDep,
    service: TokenManagementServiceDep,
) -> JSONResponse:
    """Preserve the current session and revoke all remaining sessions."""
    return APIResponse.success(
        data=await service.logout_others(
            user_id=principal.user_id,
            current_session_id=principal.session_id,
        )
    )


@router.post(
    "/logout/all",
    response_model=APIResponseModel[MessageResponse],
    summary="Logout from all devices",
)
async def logout_all(
    principal: CurrentUserDep,
    service: TokenManagementServiceDep,
) -> JSONResponse:
    """Revoke every active session, including the current one."""
    return APIResponse.success(data=await service.logout_all(user_id=principal.user_id))


__all__ = ["router"]
