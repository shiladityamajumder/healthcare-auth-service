"""File: app/modules/token_management/routes.py

Purpose:
Defines ``/auth`` JWKS publication, refresh-token rotation, and refresh/access
token logout endpoints.

Dependency flow:
HTTP request
-> route-specific token, context, rate-limit, or LogoutAccess dependency
-> TokenManagementServiceDep where persistence is required
-> token/session service and unit of work
-> APIResponse
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.common.exceptions import NotFoundError
from app.common.response import APIResponse, APIResponseModel
from app.modules.token_management.dependencies import (
    AuthRateLimitsDep,
    LogoutAccess,
    RateLimitRequestContextDep,
    RefreshRequestContextDep,
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
    """Publish configured public RS256 verification keys.

    This public endpoint resolves ``TokenManagerDep`` only; it never returns
    private key material and reports not found when no JWKS keys are configured.
    """
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
    context: RefreshRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: TokenManagementServiceDep,
) -> JSONResponse:
    """Rotate a valid refresh token and reject token-family reuse.

    The endpoint is refresh-token protected by the service/token manager;
    ``AuthRateLimitsDep`` applies the payload-aware refresh fingerprint limit.
    """
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
    context: RateLimitRequestContextDep,
    rate_limits: AuthRateLimitsDep,
    service: TokenManagementServiceDep,
) -> JSONResponse:
    """Revoke the session identified by a valid refresh token.

    This route does not require an access principal. Token validation occurs in
    the service and the specialized logout limiter keys the token fingerprint.
    """
    await rate_limits.logout(
        context=context,
        token_fingerprint=payload.refresh_token[-32:],
    )
    return APIResponse.success(data=await service.logout(payload))


@router.post(
    "/logout/others",
    response_model=APIResponseModel[MessageResponse],
    summary="Logout from every other device",
)
async def logout_others(
    principal: LogoutAccess,
    service: TokenManagementServiceDep,
) -> JSONResponse:
    """Preserve the authenticated current session and revoke all others.

    ``LogoutAccess`` validates the bearer principal/session and applies the
    sensitive API limit before the service performs user-owned revocation.
    """
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
    principal: LogoutAccess,
    service: TokenManagementServiceDep,
) -> JSONResponse:
    """Revoke every active session for the authenticated user.

    ``LogoutAccess`` protects and rate-limits this access-token-authenticated
    mutation; the principal user identifier scopes the update.
    """
    return APIResponse.success(data=await service.logout_all(user_id=principal.user_id))


__all__ = ["router"]
