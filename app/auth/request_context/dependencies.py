"""File: app/auth/request_context/dependencies.py
FastAPI dependencies for authentication request resolution.

This module resolves process-wide authentication infrastructure, validated
request metadata, bearer access tokens, persisted sessions, and authenticated
user principals.

It does not construct feature-module services and does not enforce specific
roles or permissions. Authorization dependencies belong in
``app.auth.authorization.dependencies``.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, cast

from fastapi import Depends, Request
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from sqlalchemy import select

from app.auth.authorization.claims import (
    load_authorization_claims,
)
from app.auth.infrastructure.runtime import AuthRuntime
from app.auth.request_context.context import AuthRequestContext
from app.auth.request_context.headers import (
    AuthHeaders,
    get_auth_headers,
    get_principal_assertion_headers,
    get_rate_limit_headers,
    get_session_creation_headers,
)
from app.auth.request_context.principals import UserPrincipal
from app.auth.security.tokens import (
    TokenManager,
    TokenType,
)
from app.auth.workflows.rate_limits import AuthRateLimits
from app.common.exceptions import (
    AuthenticationError,
    InfrastructureUnavailableError,
)
from app.core.di import DatabaseDep
from app.models.enums import UserStatus
from app.models.identity import Sessions, Users
from app.utils.datetime_utils import utc_now

_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="BearerAuth",
)


def get_auth_runtime(
    request: Request,
) -> AuthRuntime:
    """Return initialized process-wide authentication infrastructure.

    Args:
        request: Active FastAPI request.

    Returns:
        Initialized process-wide authentication runtime.

    Raises:
        InfrastructureUnavailableError: If application startup has not
            completed authentication infrastructure initialization.
    """
    runtime = getattr(
        request.app.state,
        "auth_runtime",
        None,
    )

    if runtime is None:
        raise InfrastructureUnavailableError(
            "Authentication infrastructure has not completed startup."
        )

    return cast(AuthRuntime, runtime)


AuthRuntimeDep = Annotated[
    AuthRuntime,
    Depends(get_auth_runtime),
]


AuthHeadersDep = Annotated[
    AuthHeaders,
    Depends(get_auth_headers),
]

RateLimitHeadersDep = Annotated[
    AuthHeaders,
    Depends(get_rate_limit_headers),
]
SessionCreationHeadersDep = Annotated[
    AuthHeaders,
    Depends(get_session_creation_headers),
]
PrincipalAssertionHeadersDep = Annotated[
    AuthHeaders,
    Depends(get_principal_assertion_headers),
]


def get_auth_request_context(
    request: Request,
    runtime: AuthRuntimeDep,
    headers: AuthHeadersDep,
) -> AuthRequestContext:
    """Build validated request-scoped authentication metadata.

    Args:
        request: Active FastAPI request.
        runtime: Process-wide authentication runtime.
        headers: Validated authentication metadata headers.

    Returns:
        Immutable authentication request context.
    """
    return AuthRequestContext.from_request(
        request,
        settings=runtime.settings,
        headers=headers,
    )


AuthRequestContextDep = Annotated[
    AuthRequestContext,
    Depends(get_auth_request_context),
]


def get_rate_limit_request_context(
    request: Request,
    runtime: AuthRuntimeDep,
    headers: RateLimitHeadersDep,
) -> AuthRequestContext:
    """Build context for anonymous workflows that only enforce rate limits."""
    return AuthRequestContext.from_request(
        request,
        settings=runtime.settings,
        headers=headers,
    )


RateLimitRequestContextDep = Annotated[
    AuthRequestContext,
    Depends(get_rate_limit_request_context),
]


def get_session_creation_request_context(
    request: Request,
    runtime: AuthRuntimeDep,
    headers: SessionCreationHeadersDep,
) -> AuthRequestContext:
    """Build context for workflows that create or rotate device sessions."""
    return AuthRequestContext.from_request(
        request,
        settings=runtime.settings,
        headers=headers,
    )


SessionCreationRequestContextDep = Annotated[
    AuthRequestContext,
    Depends(get_session_creation_request_context),
]


def get_principal_request_context(
    request: Request,
    runtime: AuthRuntimeDep,
    headers: PrincipalAssertionHeadersDep,
) -> AuthRequestContext:
    """Build context containing only bearer-principal consistency assertions."""
    return AuthRequestContext.from_request(
        request,
        settings=runtime.settings,
        headers=headers,
    )


PrincipalRequestContextDep = Annotated[
    AuthRequestContext,
    Depends(get_principal_request_context),
]


def get_token_manager(
    runtime: AuthRuntimeDep,
) -> TokenManager:
    """Return the process-wide token manager.

    Args:
        runtime: Process-wide authentication runtime.

    Returns:
        Shared JWT token manager.
    """
    return runtime.tokens


TokenManagerDep = Annotated[
    TokenManager,
    Depends(get_token_manager),
]


def get_auth_rate_limits(
    runtime: AuthRuntimeDep,
) -> AuthRateLimits:
    """Build the authentication rate-limit facade.

    The facade is lightweight and request-safe. It reuses the process-wide
    limiter and secure hashing infrastructure held by ``AuthRuntime``.

    Args:
        runtime: Process-wide authentication runtime.

    Returns:
        Authentication-specific rate-limit facade.
    """
    return AuthRateLimits(
        settings=runtime.settings,
        limiter=runtime.rate_limiter,
        hashing=runtime.hashing,
    )


AuthRateLimitsDep = Annotated[
    AuthRateLimits,
    Depends(get_auth_rate_limits),
]


async def get_current_user_principal(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer),
    ],
    database: DatabaseDep,
    runtime: AuthRuntimeDep,
    context: PrincipalRequestContextDep,
) -> UserPrincipal:
    """Validate an access token and resolve its authenticated principal.

    ``X-User-ID`` and ``X-Session-ID`` are optional consistency assertions.
    ``X-Device-ID`` is compared with persisted session metadata when both are
    present.

    None of these headers can authenticate a request without a valid signed
    access token.

    Args:
        credentials: Optional HTTP bearer credentials.
        database: Process-wide PostgreSQL adapter dependency.
        runtime: Process-wide authentication infrastructure.
        context: Validated request metadata.

    Returns:
        Authenticated user principal.

    Raises:
        AuthenticationError: If the token, claims, persisted session, account,
            or consistency assertions are invalid.
    """
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise AuthenticationError()

    payload = runtime.tokens.decode(
        credentials.credentials,
        expected_type=TokenType.ACCESS,
    )

    user_id = _uuid_claim(
        payload,
        claim_name="sub",
    )
    session_id = _uuid_claim(
        payload,
        claim_name="sid",
    )

    _validate_identity_assertions(
        context=context,
        user_id=user_id,
        session_id=session_id,
    )

    roles = _string_set_claim(
        payload,
        claim_name="roles",
    )
    permissions = _string_set_claim(
        payload,
        claim_name="permissions",
    )
    auth_methods = _string_tuple_claim(
        payload,
        claim_name="amr",
    )

    if runtime.settings.AUTH_CHECK_SESSION_ON_EACH_REQUEST:
        async with database.session() as session:
            statement = (
                select(
                    Sessions,
                    Users,
                )
                .join(
                    Users,
                    Users.id == Sessions.user_id,
                )
                .where(
                    Sessions.id == session_id,
                    Sessions.user_id == user_id,
                )
            )

            result = await session.execute(statement)
            row = result.one_or_none()

            if row is None:
                raise AuthenticationError("The access session is expired or revoked.")

            session_record = row[0]
            user = row[1]
            now = utc_now()

            _validate_persisted_session(
                session_record=session_record,
                user=user,
                context=context,
                now=now,
            )

            if runtime.settings.AUTH_REFRESH_AUTHZ_ON_EACH_REQUEST:
                claims = await load_authorization_claims(
                    session,
                    user_id=user_id,
                    now=now,
                )

                roles = frozenset(claims.roles)
                permissions = frozenset(claims.permissions)

    return UserPrincipal(
        user_id=user_id,
        session_id=session_id,
        roles=roles,
        permissions=permissions,
        auth_methods=auth_methods,
    )


CurrentUserDep = Annotated[
    UserPrincipal,
    Depends(get_current_user_principal),
]


def _uuid_claim(
    payload: Mapping[str, object],
    *,
    claim_name: str,
) -> uuid.UUID:
    """Load and validate one required UUID token claim.

    Args:
        payload: Decoded access-token claims.
        claim_name: Required UUID claim name.

    Returns:
        Parsed UUID claim.

    Raises:
        AuthenticationError: If the claim is missing or malformed.
    """
    try:
        raw_value = payload[claim_name]
    except KeyError as exc:
        raise AuthenticationError("The access token is invalid.") from exc

    try:
        return uuid.UUID(str(raw_value))
    except (TypeError, ValueError) as exc:
        raise AuthenticationError("The access token is invalid.") from exc


def _string_set_claim(
    payload: Mapping[str, object],
    *,
    claim_name: str,
) -> frozenset[str]:
    """Load an optional token claim as an immutable string set.

    Args:
        payload: Decoded access-token claims.
        claim_name: Optional collection claim name.

    Returns:
        Deduplicated immutable string values.
    """
    values = _string_sequence_claim(
        payload,
        claim_name=claim_name,
    )

    return frozenset(values)


def _string_tuple_claim(
    payload: Mapping[str, object],
    *,
    claim_name: str,
) -> tuple[str, ...]:
    """Load an optional token claim as an ordered string tuple.

    Args:
        payload: Decoded access-token claims.
        claim_name: Optional collection claim name.

    Returns:
        Ordered and deduplicated string values.
    """
    values = _string_sequence_claim(
        payload,
        claim_name=claim_name,
    )

    return tuple(dict.fromkeys(values))


def _string_sequence_claim(
    payload: Mapping[str, object],
    *,
    claim_name: str,
) -> tuple[str, ...]:
    """Validate an optional list-like string token claim.

    Args:
        payload: Decoded access-token claims.
        claim_name: Optional collection claim name.

    Returns:
        Normalized string values.

    Raises:
        AuthenticationError: If the claim is not a collection of nonblank
            strings.
    """
    raw_value = payload.get(claim_name)

    if raw_value is None:
        return ()

    if not isinstance(
        raw_value,
        (list, tuple, set, frozenset),
    ):
        raise AuthenticationError("The access token contains invalid claims.")

    normalized_values: list[str] = []

    for item in raw_value:
        if not isinstance(item, str):
            raise AuthenticationError("The access token contains invalid claims.")

        normalized = item.strip()

        if not normalized:
            raise AuthenticationError("The access token contains invalid claims.")

        normalized_values.append(normalized)

    return tuple(normalized_values)


def _validate_identity_assertions(
    *,
    context: AuthRequestContext,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
) -> None:
    """Validate optional client-supplied token consistency assertions.

    Args:
        context: Validated authentication request metadata.
        user_id: Authenticated user identifier from the signed token.
        session_id: Authenticated session identifier from the signed token.

    Raises:
        AuthenticationError: If an assertion does not match the token.
    """
    if context.asserted_user_id is not None and context.asserted_user_id != user_id:
        raise AuthenticationError("X-User-ID does not match the access token subject.")

    if context.asserted_session_id is not None and context.asserted_session_id != session_id:
        raise AuthenticationError("X-Session-ID does not match the access token session.")


def _validate_persisted_session(
    *,
    session_record: Sessions,
    user: Users,
    context: AuthRequestContext,
    now: datetime,
) -> None:
    """Validate persisted session and account state.

    The current time is supplied by the caller so every validity check during
    one request uses the same timestamp.

    Args:
        session_record: Persisted authenticated session.
        user: Persisted session owner.
        context: Validated authentication request metadata.
        now: Current timezone-aware UTC datetime.

    Raises:
        AuthenticationError: If the device assertion, session, or account is
            no longer valid.
    """
    if (
        context.device_id is not None
        and session_record.device_id is not None
        and session_record.device_id != context.device_id
    ):
        raise AuthenticationError("X-Device-ID does not match the authenticated session.")

    session_invalid = session_record.revoked_at is not None or session_record.expires_at <= now

    account_invalid = (
        user.status != UserStatus.ACTIVE
        or user.account_closed_at is not None
        or (user.locked_until is not None and user.locked_until > now)
    )

    if session_invalid or account_invalid:
        raise AuthenticationError("The access session is expired or revoked.")


__all__ = [
    "AuthHeadersDep",
    "AuthRateLimitsDep",
    "AuthRequestContextDep",
    "AuthRuntimeDep",
    "CurrentUserDep",
    "PrincipalAssertionHeadersDep",
    "PrincipalRequestContextDep",
    "RateLimitHeadersDep",
    "RateLimitRequestContextDep",
    "SessionCreationHeadersDep",
    "SessionCreationRequestContextDep",
    "TokenManagerDep",
    "get_auth_rate_limits",
    "get_auth_request_context",
    "get_auth_runtime",
    "get_current_user_principal",
    "get_principal_request_context",
    "get_rate_limit_request_context",
    "get_session_creation_request_context",
    "get_token_manager",
]
