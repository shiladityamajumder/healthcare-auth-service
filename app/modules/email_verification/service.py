"""File: app/modules/email_verification/service.py

Purpose:
Owns email-verification OTP issuance/consumption, account verification state,
and optional first-session token issuance.

Dependency flow:
EmailVerificationDep
-> request-scoped SQLAlchemyUnitOfWork
-> EmailVerificationRepository and OTPService
-> account policy and authorization-claim checks
-> optional SessionTokenIssuer/notification boundary
-> commit/rollback and response contract
"""

from __future__ import annotations

from app.auth.authorization.model_adapters import account_access_state
from app.auth.authorization.policies import AccountAccessPolicy
from app.auth.identity.normalization import normalize_email
from app.auth.identity.presentation import public_user_data
from app.auth.request_context.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.auth.security.tokens import TokenManager
from app.auth.workflows.notifications import AuthNotificationGateway, NotificationDispatcher
from app.auth.workflows.otp import IssuedOTP, OTPService
from app.auth.workflows.session_tokens import SessionTokenIssuer
from app.common.exceptions import AuthenticationError
from app.core.config import AppSettings
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.enums import OTPChannel, OTPPurpose, UserStatus
from app.models.identity import Users
from app.modules.email_verification.repositories import EmailVerificationRepository
from app.modules.email_verification.schemas import (
    EmailVerificationConfirmRequest,
    EmailVerificationRequest,
    OtpChallengeResponse,
    TokenPairResponse,
    UserResponse,
)
from app.utils.datetime_utils import utc_now


class EmailVerificationService:
    """Issue email OTPs and activate verified email identities."""

    def __init__(
        self,
        *,
        uow: SQLAlchemyUnitOfWork,
        settings: AppSettings,
        hashing: SecureHashing,
        tokens: TokenManager,
        otp: OTPService,
        notifications: AuthNotificationGateway,
    ) -> None:
        self._uow = uow
        self._settings = settings
        self._otp = otp
        self._notifications = NotificationDispatcher(notifications)
        self._issuer = SessionTokenIssuer(tokens=tokens, hashing=hashing)

    def _otp_response(self, issued: IssuedOTP) -> OtpChallengeResponse:
        """Project an issued challenge and expose its code only in allowed environments."""
        expose = self._settings.OTP_DEV_EXPOSE_CODE and self._settings.ENVIRONMENT.value in {
            "local",
            "development",
            "testing",
        }
        return OtpChallengeResponse(
            challenge_id=issued.challenge.id,
            expires_at=issued.challenge.expires_at,
            retry_after_seconds=self._settings.OTP_RESEND_COOLDOWN_SECONDS,
            development_otp=issued.code if expose else None,
        )

    async def request(
        self,
        payload: EmailVerificationRequest,
    ) -> OtpChallengeResponse:
        """Validate the destination and issue the workflow challenge."""
        email = normalize_email(str(payload.email))
        async with self._uow:
            repository = EmailVerificationRepository(self._uow.session)
            # When delivery is enabled, load the user here and set
            # ``should_deliver`` only for an unverified account.
            issued = await self._otp.issue(
                repository=repository,
                channel=OTPChannel.EMAIL.value,
                destination=email,
                purpose=OTPPurpose.VERIFY_EMAIL.value,
            )
        # External email delivery intentionally remains paused. The OTP is
        # still issued and persisted, so uncomment this block after the email
        # provider is configured and delivery should be enabled.
        # if should_deliver:
        #     await self._notifications.send_otp(
        #         channel=OTPChannel.EMAIL.value,
        #         destination=email,
        #         code=issued.code,
        #         purpose=OTPPurpose.VERIFY_EMAIL.value,
        #         expires_in_seconds=self._settings.OTP_TTL_SECONDS,
        #     )
        return self._otp_response(issued)

    async def confirm(
        self,
        payload: EmailVerificationConfirmRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Confirm the submitted proof and complete the workflow."""
        email = normalize_email(str(payload.email))
        pending_error: AuthenticationError | None = None
        result: TokenPairResponse | None = None
        async with self._uow:
            repository = EmailVerificationRepository(self._uow.session)
            # Verification locks and consumes the challenge before account state
            # is changed or a session can be issued.
            verification = await self._otp.verify(
                repository=repository,
                challenge_id=payload.challenge_id,
                channel=OTPChannel.EMAIL.value,
                destination=email,
                purpose=OTPPurpose.VERIFY_EMAIL.value,
                code=payload.code,
            )
            user = await repository.get_user_by_email(email, for_update=True)
            if not verification.valid or user is None or user.email_verified_at is not None:
                pending_error = AuthenticationError("The verification code is invalid or expired.")
            else:
                try:
                    AccountAccessPolicy.ensure_login_allowed(
                        account_access_state(user),
                        allow_pending=True,
                    )
                except AuthenticationError as exc:
                    pending_error = exc
                else:
                    repository.mark_email_verified(user, verified_at=utc_now())
                    if user.status == UserStatus.PENDING_VERIFICATION:
                        user.status = UserStatus.ACTIVE
                    result = await self._issue_tokens(
                        user=user,
                        repository=repository,
                        payload=payload,
                        context=context,
                    )
        # Raise after the transaction preserves OTP attempt/consumption state.
        if pending_error is not None:
            raise pending_error
        assert result is not None
        return result

    async def _issue_tokens(
        self,
        *,
        user: Users,
        repository: EmailVerificationRepository,
        payload: EmailVerificationConfirmRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Load current claims and stage the verified user's first session."""
        claims = await repository.authorization_claims(user_id=user.id, now=utc_now())
        profile = await repository.get_active_profile(user.id)
        user_dto = UserResponse.model_validate(
            public_user_data(
                user,
                profile=profile,
                roles=claims.roles,
                permissions=claims.permissions,
            )
        )
        issued = self._issuer.issue(
            user_id=user.id,
            roles=claims.roles,
            permissions=claims.permissions,
            session_writer=repository,
            request_context=context,
            device=payload,
            auth_methods=["email_verification"],
        )
        return TokenPairResponse(
            access_token=issued.access_token,
            refresh_token=issued.refresh_token,
            access_expires_at=issued.access_expires_at,
            refresh_expires_at=issued.refresh_expires_at,
            user=user_dto,
        )


__all__ = ["EmailVerificationService"]
