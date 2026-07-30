"""File: app/modules/token_management/service.py

Purpose:
Owns refresh-token rotation/replay handling and refresh- or access-principal
session revocation use cases.

Dependency flow:
TokenManagementServiceDep
-> TokenManager verification and SecureHashing
-> request-scoped SQLAlchemyUnitOfWork
-> TokenRepository on the shared session
-> token-family/session validation and mutation
-> commit/rollback and response contract
"""

from __future__ import annotations

import uuid

from app.auth.authorization.model_adapters import account_access_state
from app.auth.authorization.policies import AccountAccessPolicy
from app.auth.identity.presentation import public_user_data
from app.auth.request_context.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.auth.security.tokens import TokenManager, TokenType
from app.common.exceptions import (
    AuthenticationError,
    RefreshTokenReuseError,
    SessionRevokedError,
)
from app.db.uow import SQLAlchemyUnitOfWork
from app.modules.token_management.repositories import TokenRepository
from app.modules.token_management.schemas import (
    LogoutRequest,
    MessageResponse,
    RefreshTokenRequest,
    TokenPairResponse,
    UserResponse,
)
from app.utils.datetime_utils import utc_now


class TokenManagementService:
    """Rotate refresh tokens and revoke current or related sessions."""

    def __init__(
        self,
        *,
        uow: SQLAlchemyUnitOfWork,
        hashing: SecureHashing,
        tokens: TokenManager,
    ) -> None:
        self._uow = uow
        self._hashing = hashing
        self._tokens = tokens

    async def refresh(
        self,
        payload: RefreshTokenRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Rotate the refresh token and return a new token pair."""
        claims = self._tokens.decode(
            payload.refresh_token,
            expected_type=TokenType.REFRESH,
        )
        try:
            user_id = uuid.UUID(str(claims["sub"]))
            session_id = uuid.UUID(str(claims["sid"]))
            family_id = uuid.UUID(str(claims["fam"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("The refresh token is invalid.") from exc

        pending_error: AuthenticationError | None = None
        result: TokenPairResponse | None = None
        async with self._uow:
            repository = TokenRepository(self._uow.session)
            # The session row lock serializes refresh rotation and reuse
            # detection for one token family.
            session = await repository.get_session(session_id, for_update=True)
            now = utc_now()
            if session is None or session.user_id != user_id:
                pending_error = AuthenticationError("The refresh token is invalid.")
            elif session.token_family_id != family_id:
                await repository.revoke_family(
                    family_id=session.token_family_id,
                    revoked_at=now,
                    reason="refresh_family_mismatch",
                )
                pending_error = RefreshTokenReuseError()
            elif session.revoked_at is not None or session.expires_at <= now:
                pending_error = SessionRevokedError()
            elif session.refresh_token_hash != self._hashing.token_hash(payload.refresh_token):
                await repository.revoke_family(
                    family_id=session.token_family_id,
                    revoked_at=now,
                    reason="refresh_token_reuse_detected",
                )
                pending_error = RefreshTokenReuseError()
            else:
                user = await repository.get_user(user_id, for_update=True)
                if user is None:
                    pending_error = AuthenticationError("The refresh token is invalid.")
                else:
                    try:
                        AccountAccessPolicy.ensure_login_allowed(account_access_state(user))
                    except AuthenticationError as exc:
                        session.revoked_at = now
                        session.revoke_reason = "account_not_available"
                        pending_error = exc
                    else:
                        authz = await repository.authorization_claims(
                            user_id=user.id,
                            now=now,
                        )
                        refresh = self._tokens.create_refresh_token(
                            user_id=user.id,
                            session_id=session.id,
                            family_id=session.token_family_id,
                        )
                        access = self._tokens.create_access_token(
                            user_id=user.id,
                            session_id=session.id,
                            roles=authz.roles,
                            permissions=authz.permissions,
                            auth_methods=["refresh_token"],
                        )
                        session.refresh_token_hash = self._hashing.token_hash(refresh.token)
                        session.expires_at = refresh.expires_at
                        session.last_seen_at = now
                        session.ip_address = context.ip_address
                        session.user_agent = context.user_agent
                        session.device_id = payload.device_id or session.device_id
                        session.device_type = payload.device_type or session.device_type
                        profile = await repository.get_active_profile(user.id)
                        user_dto = UserResponse.model_validate(
                            public_user_data(
                                user,
                                profile=profile,
                                roles=authz.roles,
                                permissions=authz.permissions,
                            )
                        )
                        result = TokenPairResponse(
                            access_token=access.token,
                            refresh_token=refresh.token,
                            access_expires_at=access.expires_at,
                            refresh_expires_at=refresh.expires_at,
                            user=user_dto,
                        )
        # Defer the error until family/session revocation mutations commit.
        if pending_error is not None:
            raise pending_error
        assert result is not None
        return result

    async def logout(self, payload: LogoutRequest) -> MessageResponse:
        """Revoke the session identified by the supplied refresh token."""
        claims = self._tokens.decode(
            payload.refresh_token,
            expected_type=TokenType.REFRESH,
        )
        try:
            session_id = uuid.UUID(str(claims["sid"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("The refresh token is invalid.") from exc
        async with self._uow:
            session = await TokenRepository(self._uow.session).get_session(
                session_id,
                for_update=True,
            )
            if session is not None and session.revoked_at is None:
                session.revoked_at = utc_now()
                session.revoke_reason = "user_logout"
        return MessageResponse(message="The session has been logged out.")

    async def logout_others(
        self,
        *,
        user_id: uuid.UUID,
        current_session_id: uuid.UUID,
    ) -> MessageResponse:
        """Revoke every user session except the current session."""
        async with self._uow:
            await TokenRepository(self._uow.session).revoke_user_sessions(
                user_id=user_id,
                revoked_at=utc_now(),
                reason="user_logout_others",
                except_session_id=current_session_id,
            )
        return MessageResponse(message="All other sessions have been logged out.")

    async def logout_all(self, *, user_id: uuid.UUID) -> MessageResponse:
        """Revoke every active session for the user."""
        async with self._uow:
            await TokenRepository(self._uow.session).revoke_user_sessions(
                user_id=user_id,
                revoked_at=utc_now(),
                reason="user_logout_all",
            )
        return MessageResponse(message="All sessions have been logged out.")


__all__ = ["TokenManagementService"]
