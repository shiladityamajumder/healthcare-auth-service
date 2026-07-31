"""File: app/modules/password_management/service.py

Purpose:
Owns recovery OTP issuance/proof consumption, password history enforcement,
credential replacement, and session rotation/revocation.

Dependency flow:
PasswordManagementServiceDep
-> password/reset-token/account policy components
-> request-scoped SQLAlchemyUnitOfWork
-> PasswordRepository and OTPService
-> password history plus session mutations
-> commit/rollback and response contract
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.auth.authorization.model_adapters import account_access_state, password_history_state
from app.auth.authorization.policies import AccountAccessPolicy, PasswordHistoryPolicy
from app.auth.identity.normalization import normalize_email, normalize_phone, phone_destination
from app.auth.request_context.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.auth.security.passwords import PasswordManager
from app.auth.security.tokens import TokenManager, TokenType
from app.auth.workflows.notifications import AuthNotificationGateway, NotificationDispatcher
from app.auth.workflows.otp import IssuedOTP, OTPService
from app.auth.workflows.session_tokens import (
    SessionTokenIssuer,
    build_token_pair_response,
)
from app.common.exceptions import AuthenticationError, ConflictError, NotFoundError, ValidationError
from app.core.config import AppSettings
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.enums import OTPChannel, OTPPurpose
from app.models.identity import Users
from app.modules.password_management.repositories import PasswordRepository
from app.modules.password_management.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    IdentityRequest,
    OtpChallengeResponse,
    ResetPasswordProofResponse,
    ResetPasswordWithTokenRequest,
    SetPasswordRequest,
    TokenPairResponse,
    VerifyResetOtpRequest,
)
from app.utils.datetime_utils import utc_now


@dataclass(frozen=True, slots=True)
class _ResolvedIdentity:
    channel: str
    destination: str
    email: str | None = None
    phone_country_code: str | None = None
    phone_number: str | None = None


def _resolve_identity(payload: IdentityRequest) -> _ResolvedIdentity:
    """Normalize the email or phone destination selected by the request."""
    channel = payload.channel
    if channel == OTPChannel.EMAIL.value:
        email_value = payload.email
        if email_value is None:
            raise ValidationError("Email is required.")
        email = normalize_email(str(email_value))
        return _ResolvedIdentity(channel=channel, destination=email, email=email)
    if channel == OTPChannel.SMS.value:
        country, phone = normalize_phone(
            payload.phone_country_code or "",
            payload.phone_number or "",
        )
        return _ResolvedIdentity(
            channel=channel,
            destination=phone_destination(country, phone),
            phone_country_code=country,
            phone_number=phone,
        )
    raise ValidationError("Unsupported OTP channel.")


class PasswordManagementService:
    """Implement secure password recovery and authenticated password changes."""

    def __init__(
        self,
        *,
        uow: SQLAlchemyUnitOfWork,
        settings: AppSettings,
        passwords: PasswordManager,
        hashing: SecureHashing,
        tokens: TokenManager,
        otp: OTPService,
        notifications: AuthNotificationGateway,
    ) -> None:
        self._uow = uow
        self._settings = settings
        self._passwords = passwords
        self._hashing = hashing
        self._tokens = tokens
        self._otp = otp
        self._notifications = NotificationDispatcher(notifications)
        self._history = PasswordHistoryPolicy(settings=settings, passwords=passwords)
        self._issuer = SessionTokenIssuer(tokens=tokens, hashing=hashing)

    async def _get_identity_user(
        self,
        repository: PasswordRepository,
        identity: _ResolvedIdentity,
        *,
        for_update: bool = False,
    ) -> Users | None:
        """Load the user selected by the already normalized recovery identity."""
        if identity.email is not None:
            return await repository.get_by_email(identity.email, for_update=for_update)
        assert identity.phone_country_code is not None
        assert identity.phone_number is not None
        return await repository.get_by_phone(
            identity.phone_country_code,
            identity.phone_number,
            for_update=for_update,
        )

    def _otp_response(self, issued: IssuedOTP) -> OtpChallengeResponse:
        """Project reset challenge metadata with gated development code exposure."""
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

    async def _issue_tokens(
        self,
        *,
        user: Users,
        repository: PasswordRepository,
        context: AuthRequestContext,
        auth_method: str,
    ) -> TokenPairResponse:
        """Stage the sole post-password-change session."""
        profile = await repository.get_active_profile(user.id)
        issued = self._issuer.issue(
            user_id=user.id,
            session_writer=repository,
            request_context=context,
            auth_methods=[auth_method],
        )
        return build_token_pair_response(issued=issued, user=user, profile=profile)

    async def forgot(self, payload: ForgotPasswordRequest) -> OtpChallengeResponse:
        """Issue a generic password-reset challenge without account enumeration."""
        identity = _resolve_identity(payload)
        purpose = self._reset_purpose(identity.channel)
        async with self._uow:
            repository = PasswordRepository(self._uow.session)
            # When delivery is enabled, resolve the user here and set
            # ``should_deliver`` only for an active account.
            issued = await self._otp.issue(
                repository=repository,
                channel=identity.channel,
                destination=identity.destination,
                purpose=purpose,
            )
        # External email/SMS delivery intentionally remains paused. The OTP is
        # still issued and persisted, so uncomment this block after the chosen
        # notification provider is configured and delivery should be enabled.
        # if should_deliver:
        #     await self._notifications.send_otp(
        #         channel=identity.channel,
        #         destination=identity.destination,
        #         code=issued.code,
        #         purpose=purpose,
        #         expires_in_seconds=self._settings.OTP_TTL_SECONDS,
        #     )
        return self._otp_response(issued)

    async def verify_reset_otp(
        self,
        payload: VerifyResetOtpRequest,
    ) -> ResetPasswordProofResponse:
        """Consume an OTP and issue a short-lived, one-time reset proof."""
        identity = _resolve_identity(payload)
        purpose = self._reset_purpose(identity.channel)
        pending_error: AuthenticationError | None = None
        response: ResetPasswordProofResponse | None = None
        async with self._uow:
            repository = PasswordRepository(self._uow.session)
            # Verification row-locks and consumes the OTP before a reset proof
            # can be signed, preserving the challenge's one-time property.
            verification = await self._otp.verify(
                repository=repository,
                challenge_id=payload.challenge_id,
                channel=identity.channel,
                destination=identity.destination,
                purpose={purpose, OTPPurpose.PASSWORD_RESET.value},
                code=payload.code,
            )
            user = await self._get_identity_user(
                repository,
                identity,
                for_update=True,
            )
            if not verification.valid or user is None:
                pending_error = AuthenticationError(
                    "The password-reset code is invalid or expired."
                )
            else:
                try:
                    AccountAccessPolicy.ensure_login_allowed(
                        account_access_state(user),
                        verified_channel=identity.channel,
                    )
                except AuthenticationError as exc:
                    pending_error = exc
                else:
                    proof = self._tokens.create_password_reset_token(
                        user_id=user.id,
                        challenge_id=payload.challenge_id,
                        channel=identity.channel,
                        destination_hash=self._hashing.destination_hash(identity.destination),
                    )
                    response = ResetPasswordProofResponse(
                        reset_token=proof.token,
                        expires_at=proof.expires_at,
                    )
        if pending_error is not None:
            raise pending_error
        assert response is not None
        return response

    async def reset_with_token(
        self,
        payload: ResetPasswordWithTokenRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Redeem a reset proof, replace the password, and rotate sessions."""
        claims = self._tokens.decode(
            payload.reset_token,
            expected_type=TokenType.PASSWORD_RESET,
        )
        try:
            user_id = uuid.UUID(str(claims["sub"]))
            challenge_id = uuid.UUID(str(claims["challenge_id"]))
            destination_hash = str(claims["destination_hash"])
            channel = OTPChannel(str(claims["channel"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("The password-reset proof is invalid.") from exc

        accepted_purposes = {
            self._reset_purpose(channel.value),
            OTPPurpose.PASSWORD_RESET.value,
        }
        async with self._uow:
            repository = PasswordRepository(self._uow.session)
            # Lock the consumed challenge so concurrent reset-proof redemption
            # cannot update the same account twice.
            challenge = await repository.get_for_update(challenge_id)
            now = utc_now()
            if (
                challenge is None
                or challenge.consumed_at is None
                or challenge.blocked_at is not None
                or challenge.channel != channel.value
                or challenge.purpose not in accepted_purposes
                or challenge.destination_hash != destination_hash
            ):
                raise AuthenticationError(
                    "The password-reset proof is invalid, expired, or already used."
                )

            user = await repository.get_by_id(user_id, for_update=True)
            if user is None:
                raise AuthenticationError("The password-reset proof is invalid.")
            AccountAccessPolicy.ensure_login_allowed(account_access_state(user))
            self._passwords.validate_strength(
                payload.new_password,
                email=user.email,
                phone_number=user.phone_number,
            )
            await self._history.ensure_not_reused(
                users=repository,
                user=password_history_state(user),
                new_password=payload.new_password,
            )
            new_hash = await self._passwords.hash(payload.new_password)
            repository.update_password_hash(user, new_hash)
            repository.reset_failed_login_count(user)
            repository.add_password_history(user_id=user.id, password_hash=new_hash)
            # Revoke older sessions before issuing the sole replacement session
            # within this transaction.
            await repository.revoke_user_sessions(
                user_id=user.id,
                revoked_at=now,
                reason="password_reset",
            )
            challenge.blocked_at = now
            return await self._issue_tokens(
                user=user,
                repository=repository,
                context=context,
                auth_method="password_reset",
            )

    async def change(
        self,
        *,
        user_id: uuid.UUID,
        payload: ChangePasswordRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Change the authenticated user password and rotate sessions."""
        async with self._uow:
            repository = PasswordRepository(self._uow.session)
            user = await repository.get_by_id(user_id, for_update=True)
            if user is None:
                raise NotFoundError("The user was not found.")
            if not user.password_hash or not await self._passwords.verify(
                user.password_hash,
                payload.current_password,
            ):
                raise AuthenticationError("The current password is incorrect.")
            self._passwords.validate_strength(
                payload.new_password,
                email=user.email,
                phone_number=user.phone_number,
            )
            await self._history.ensure_not_reused(
                users=repository,
                user=password_history_state(user),
                new_password=payload.new_password,
            )
            new_hash = await self._passwords.hash(payload.new_password)
            repository.update_password_hash(user, new_hash)
            repository.add_password_history(user_id=user.id, password_hash=new_hash)
            # A credential change invalidates all existing sessions before the
            # replacement token pair is staged.
            await repository.revoke_user_sessions(
                user_id=user.id,
                revoked_at=utc_now(),
                reason="password_changed",
            )
            return await self._issue_tokens(
                user=user,
                repository=repository,
                context=context,
                auth_method="password",
            )

    async def set(
        self,
        *,
        user_id: uuid.UUID,
        payload: SetPasswordRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Set the initial password for an OTP-only account."""
        async with self._uow:
            repository = PasswordRepository(self._uow.session)
            user = await repository.get_by_id(user_id, for_update=True)
            if user is None:
                raise NotFoundError("The user was not found.")
            if user.password_hash:
                raise ConflictError("A password is already configured for this account.")
            self._passwords.validate_strength(
                payload.new_password,
                email=user.email,
                phone_number=user.phone_number,
            )
            new_hash = await self._passwords.hash(payload.new_password)
            repository.update_password_hash(user, new_hash)
            repository.add_password_history(user_id=user.id, password_hash=new_hash)
            # Initial password setup also rotates sessions to bind future access
            # to the newly established credential state.
            await repository.revoke_user_sessions(
                user_id=user.id,
                revoked_at=utc_now(),
                reason="password_set",
            )
            return await self._issue_tokens(
                user=user,
                repository=repository,
                context=context,
                auth_method="password_set",
            )

    @staticmethod
    def _reset_purpose(channel: str) -> str:
        """Map the validated recovery channel to its purpose-specific OTP value."""
        if channel == OTPChannel.EMAIL.value:
            return OTPPurpose.PASSWORD_RESET_EMAIL.value
        return OTPPurpose.PASSWORD_RESET_PHONE.value


__all__ = ["PasswordManagementService"]
