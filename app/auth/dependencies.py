"""FastAPI dependencies for shared authentication and authorization.

This module resolves request metadata and validates bearer tokens. It does not
construct registration, login, password, session, or administration services.
Those dependencies live in their owning vertical modules.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from app.auth.authorization import load_authorization_claims
from app.auth.context import AuthRequestContext
from app.auth.headers import AuthHeaders, get_auth_headers
from app.auth.principals import UserPrincipal
from app.auth.rate_limits import AuthRateLimits
from app.auth.runtime import AuthRuntime
from app.auth.security import TokenManager, TokenType
from app.common.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InfrastructureUnavailableError,
)
from app.core.di import DatabaseDep
from app.models.enums import UserStatus
from app.models.identity import Sessions, Users
from app.utils.datetime_utils import utc_now

_bearer = HTTPBearer(auto_error=False, scheme_name="BearerAuth")


def get_auth_runtime(request: Request) -> AuthRuntime:
    """Return the initialized process-wide authentication runtime."""
    runtime = getattr(request.app.state, "auth_runtime", None)
    if runtime is None:
        raise InfrastructureUnavailableError(
            "Authentication infrastructure has not completed startup."
        )
    return runtime


AuthRuntimeDep = Annotated[AuthRuntime, Depends(get_auth_runtime)]
AuthHeadersDep = Annotated[AuthHeaders, Depends(get_auth_headers)]


def get_token_manager(runtime: AuthRuntimeDep) -> TokenManager:
    """Return the process-wide JWT manager."""
    return runtime.tokens


def get_auth_request_context(
    request: Request,
    runtime: AuthRuntimeDep,
    headers: AuthHeadersDep,
) -> AuthRequestContext:
    """Build request context from trusted connection data and typed headers."""
    return AuthRequestContext.from_request(request, runtime.settings, headers=headers)


def get_auth_rate_limits(runtime: AuthRuntimeDep) -> AuthRateLimits:
    """Return the authentication rate-limit facade."""
    return AuthRateLimits(
        settings=runtime.settings,
        limiter=runtime.rate_limiter,
        hashing=runtime.hashing,
    )


async def get_current_user_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    database: DatabaseDep,
    runtime: AuthRuntimeDep,
    headers: AuthHeadersDep,
) -> UserPrincipal:
    """Validate a bearer access token and its persisted user session.

    ``X-User-ID`` and ``X-Session-ID`` are optional consistency assertions only.
    ``X-Device-ID`` is checked against persisted session metadata when both are
    available. None of these headers can authenticate a caller by themselves.
    """
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise AuthenticationError()

    payload = runtime.tokens.decode(
        credentials.credentials,
        expected_type=TokenType.ACCESS,
    )
    try:
        user_id = uuid.UUID(str(payload["sub"]))
        session_id = uuid.UUID(str(payload["sid"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthenticationError("The access token is invalid.") from exc

    if headers.user_id is not None and headers.user_id != user_id:
        raise AuthenticationError("X-User-ID does not match the access token subject.")
    if headers.session_id is not None and headers.session_id != session_id:
        raise AuthenticationError("X-Session-ID does not match the access token session.")

    roles = frozenset(str(item) for item in payload.get("roles", []))
    permissions = frozenset(str(item) for item in payload.get("permissions", []))

    if runtime.settings.AUTH_CHECK_SESSION_ON_EACH_REQUEST:
        async with database.session() as session:
            session_record = await session.scalar(
                select(Sessions).where(Sessions.id == session_id)
            )
            user = await session.scalar(select(Users).where(Users.id == user_id))
            now = utc_now()

            if (
                session_record is not None
                and headers.device_id is not None
                and session_record.device_id is not None
                and session_record.device_id != headers.device_id
            ):
                raise AuthenticationError(
                    "X-Device-ID does not match the authenticated session."
                )

            if (
                session_record is None
                or session_record.user_id != user_id
                or session_record.revoked_at is not None
                or session_record.expires_at <= now
                or user is None
                or user.status != UserStatus.ACTIVE
                or user.account_closed_at is not None
            ):
                raise AuthenticationError("The access session is expired or revoked.")

            if runtime.settings.AUTH_REFRESH_AUTHZ_ON_EACH_REQUEST:
                claims = await load_authorization_claims(
                    session, user_id=user_id, now=now
                )
                roles = frozenset(claims.roles)
                permissions = frozenset(claims.permissions)

    return UserPrincipal(
        user_id=user_id,
        session_id=session_id,
        roles=roles,
        permissions=permissions,
        auth_methods=tuple(str(item) for item in payload.get("amr", [])),
    )


def require_permissions(*required: str) -> Callable[..., object]:
    """Return a dependency that requires every supplied permission code."""
    normalized = frozenset(item.strip() for item in required if item.strip())

    async def dependency(
        principal: Annotated[UserPrincipal, Depends(get_current_user_principal)],
    ) -> UserPrincipal:
        """Resolve the current principal and enforce required permissions."""
        missing = normalized.difference(principal.permissions)
        if missing:
            raise AuthorizationError(
                "One or more required permissions are missing.",
                details={"missing_permissions": sorted(missing)},
            )
        return principal

    return dependency


def require_roles(*required: str) -> Callable[..., object]:
    """Return a dependency that requires every supplied role code."""
    normalized = frozenset(item.strip() for item in required if item.strip())

    async def dependency(
        principal: Annotated[UserPrincipal, Depends(get_current_user_principal)],
    ) -> UserPrincipal:
        """Resolve the current principal and enforce required roles."""
        missing = normalized.difference(principal.roles)
        if missing:
            raise AuthorizationError(
                "One or more required roles are missing.",
                details={"missing_roles": sorted(missing)},
            )
        return principal

    return dependency


AuthRequestContextDep = Annotated[AuthRequestContext, Depends(get_auth_request_context)]
AuthRateLimitsDep = Annotated[AuthRateLimits, Depends(get_auth_rate_limits)]
TokenManagerDep = Annotated[TokenManager, Depends(get_token_manager)]
CurrentUserDep = Annotated[UserPrincipal, Depends(get_current_user_principal)]


__all__ = [
    "AuthHeadersDep",
    "AuthRateLimitsDep",
    "AuthRequestContextDep",
    "AuthRuntimeDep",
    "CurrentUserDep",
    "TokenManagerDep",
    "get_auth_request_context",
    "get_auth_runtime",
    "get_current_user_principal",
    "require_permissions",
    "require_roles",
]
