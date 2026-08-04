"""File: app/modules/login/service.py

Purpose:
Owns password and phone-OTP authentication, account policy checks, login
attempt state, and first-class device session/token issuance.

Dependency flow:
PasswordLoginDep or PhoneOtpLoginDep
-> request-scoped SQLAlchemyUnitOfWork
-> LoginRepository and password/OTP policy components
-> authorization claims and SessionTokenIssuer
-> staged audit/session mutations
-> commit/rollback and token response
"""

from __future__ import annotations

from datetime import timedelta

from app.auth.authorization.model_adapters import account_access_state
from app.auth.authorization.policies import AccountAccessPolicy
from app.auth.identity.normalization import normalize_email, normalize_phone, phone_destination
from app.auth.request_context.context import AuthRequestContext, request_uuid
from app.auth.security.hashing import SecureHashing
from app.auth.security.passwords import PasswordManager
from app.auth.security.tokens import TokenManager
from app.auth.workflows.notifications import AuthNotificationGateway, NotificationDispatcher
from app.auth.workflows.otp import IssuedOTP, OTPService
from app.auth.workflows.session_tokens import (
    SessionTokenIssuer,
    build_token_pair_response,
)
from app.common.exceptions import AuthenticationError, InvalidCredentialsError
from app.core.config import AppSettings
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.enums import OTPChannel, OTPPurpose
from app.models.identity import Users
from app.modules.login.repositories import LoginRepository
from app.modules.login.schemas import (
    OtpChallengeResponse,
    PasswordLoginRequest,
    PhoneOtpLoginRequest,
    PhoneOtpLoginVerifyRequest,
    TokenPairResponse,
)
from app.utils.datetime_utils import utc_now


class _LoginBase:
    def __init__(
        self,
        *,
        uow: SQLAlchemyUnitOfWork,
        settings: AppSettings,
        hashing: SecureHashing,
        tokens: TokenManager,
    ) -> None:
        self._uow = uow
        self._settings = settings
        self._hashing = hashing
        self._issuer = SessionTokenIssuer(tokens=tokens, hashing=hashing)

    async def _issue_tokens(
        self,
        *,
        user: Users,
        repository: LoginRepository,
        context: AuthRequestContext,
        auth_method: str,
    ) -> TokenPairResponse:
        """Stage a session/token pair in the active transaction."""
        profile = await repository.get_active_profile(user.id)
        issued = self._issuer.issue(
            user_id=user.id,
            session_writer=repository,
            request_context=context,
            auth_methods=[auth_method],
        )
        return build_token_pair_response(
            issued=issued,
            user=user,
            profile=profile,
        )

    @staticmethod
    def _record_attempt(
        *,
        repository: LoginRepository,
        user: Users | None,
        identifier_hash: str,
        success: bool,
        failure_code: str | None,
        context: AuthRequestContext,
    ) -> None:
        """Stage a privacy-preserving login audit record in the current transaction."""
        repository.add_login_attempt(
            user_id=user.id if user is not None else None,
            identifier_hash=identifier_hash,
            success=success,
            failure_code=failure_code,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            request_id=request_uuid(context.request_id),
        )


class PasswordLoginService(_LoginBase):
    """Authenticate email or phone identities using a password."""

    def __init__(
        self,
        *,
        uow: SQLAlchemyUnitOfWork,
        settings: AppSettings,
        passwords: PasswordManager,
        hashing: SecureHashing,
        tokens: TokenManager,
    ) -> None:
        super().__init__(
            uow=uow,
            settings=settings,
            hashing=hashing,
            tokens=tokens,
        )
        self._passwords = passwords

    async def login(
        self,
        payload: PasswordLoginRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Authenticate credentials and create a persisted user session."""
        if payload.channel == "email":
            assert payload.email is not None
            email = normalize_email(str(payload.email))
            identifier = email
            phone: tuple[str, str] | None = None
            verified_channel = OTPChannel.EMAIL.value
        else:
            assert payload.phone_country_code is not None
            assert payload.phone_number is not None
            phone = normalize_phone(
                payload.phone_country_code,
                payload.phone_number,
            )
            email = None
            identifier = phone_destination(*phone)
            verified_channel = OTPChannel.SMS.value

        pending_error: InvalidCredentialsError | None = None
        result: TokenPairResponse | None = None
        async with self._uow:
            repository = LoginRepository(self._uow.session)
            if email is not None:
                user = await repository.get_by_email(email, for_update=True)
            else:
                assert phone is not None
                user = await repository.get_by_phone(phone[0], phone[1], for_update=True)
            identifier_hash = self._hashing.identifier_hash(identifier)
            if user is None:
                # Run a real Argon2 verification path for unknown identities to
                # reduce timing differences that could reveal account existence.
                await self._passwords.verify_dummy(payload.password)
                self._record_attempt(
                    repository=repository,
                    user=None,
                    identifier_hash=identifier_hash,
                    success=False,
                    failure_code="INVALID_CREDENTIALS",
                    context=context,
                )
                pending_error = InvalidCredentialsError()
            else:
                result, pending_error = await self._authenticate_existing(
                    user=user,
                    repository=repository,
                    identifier_hash=identifier_hash,
                    payload=payload,
                    context=context,
                    verified_channel=verified_channel,
                )
        # Raise only after the unit of work commits attempt/lockout state.
        if pending_error is not None:
            raise pending_error
        assert result is not None
        return result

    async def _authenticate_existing(
        self,
        *,
        user: Users,
        repository: LoginRepository,
        identifier_hash: str,
        payload: PasswordLoginRequest,
        context: AuthRequestContext,
        verified_channel: str,
    ) -> tuple[TokenPairResponse | None, InvalidCredentialsError | None]:
        """Validate credentials/account state and stage audit/session mutations."""
        now = utc_now()
        if user.password_hash:
            password_valid = await self._passwords.verify(
                user.password_hash,
                payload.password,
            )
        else:
            await self._passwords.verify_dummy(payload.password)
            password_valid = False

        if user.locked_until and user.locked_until > now:
            self._record_attempt(
                repository=repository,
                user=user,
                identifier_hash=identifier_hash,
                success=False,
                failure_code="ACCOUNT_TEMPORARILY_LOCKED",
                context=context,
            )
            return None, InvalidCredentialsError()

        if not password_valid:
            failed_count = repository.increment_failed_login_count(user)
            if failed_count >= self._settings.LOGIN_MAX_FAILED_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=self._settings.LOGIN_LOCKOUT_MINUTES)
            self._record_attempt(
                repository=repository,
                user=user,
                identifier_hash=identifier_hash,
                success=False,
                failure_code="INVALID_CREDENTIALS",
                context=context,
            )
            return None, InvalidCredentialsError()

        try:
            AccountAccessPolicy.ensure_login_allowed(
                account_access_state(user),
                verified_channel=verified_channel,
            )
        except AuthenticationError:
            self._record_attempt(
                repository=repository,
                user=user,
                identifier_hash=identifier_hash,
                success=False,
                failure_code="ACCOUNT_NOT_AVAILABLE",
                context=context,
            )
            return None, InvalidCredentialsError()

        repository.reset_failed_login_count(user)
        user.last_login_at = now
        if user.password_hash and self._passwords.needs_rehash(user.password_hash):
            repository.update_password_hash(
                user,
                await self._passwords.hash(payload.password),
            )
        self._record_attempt(
            repository=repository,
            user=user,
            identifier_hash=identifier_hash,
            success=True,
            failure_code=None,
            context=context,
        )
        result = await self._issue_tokens(
            user=user,
            repository=repository,
            context=context,
            auth_method="password",
        )
        return result, None


class PhoneOtpLoginService(_LoginBase):
    """Issue and verify phone OTP login challenges."""

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
        super().__init__(
            uow=uow,
            settings=settings,
            hashing=hashing,
            tokens=tokens,
        )
        self._otp = otp
        self._notifications = NotificationDispatcher(notifications)

    def _otp_response(self, issued: IssuedOTP) -> OtpChallengeResponse:
        """Project challenge metadata with environment-gated development code exposure."""
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

    async def request(self, payload: PhoneOtpLoginRequest) -> OtpChallengeResponse:
        """Validate the destination and issue the workflow challenge."""
        country, phone = normalize_phone(
            payload.phone_country_code,
            payload.phone_number,
        )
        destination = phone_destination(country, phone)
        async with self._uow:
            repository = LoginRepository(self._uow.session)
            # When delivery is enabled, load the user here and set
            # ``should_deliver`` only for an active account.
            issued = await self._otp.issue(
                repository=repository,
                channel=OTPChannel.SMS.value,
                destination=destination,
                purpose=OTPPurpose.LOGIN_PHONE.value,
            )
        # External SMS delivery intentionally remains paused. The OTP is still
        # issued and persisted, so uncomment this block when the provider is
        # configured and delivery should be enabled.
        # if should_deliver:
        #     await self._notifications.send_otp(
        #         channel=OTPChannel.SMS.value,
        #         destination=destination,
        #         code=issued.code,
        #         purpose=OTPPurpose.LOGIN_PHONE.value,
        #         expires_in_seconds=self._settings.OTP_TTL_SECONDS,
        #     )
        return self._otp_response(issued)

    async def verify(
        self,
        payload: PhoneOtpLoginVerifyRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Verify the submitted proof and complete the workflow."""
        country, phone = normalize_phone(
            payload.phone_country_code,
            payload.phone_number,
        )
        destination = phone_destination(country, phone)
        pending_error: InvalidCredentialsError | None = None
        result: TokenPairResponse | None = None
        async with self._uow:
            repository = LoginRepository(self._uow.session)
            # OTP verification locks and consumes the challenge before session
            # issuance can succeed.
            verification = await self._otp.verify(
                repository=repository,
                challenge_id=payload.challenge_id,
                channel=OTPChannel.SMS.value,
                destination=destination,
                purpose=OTPPurpose.LOGIN_PHONE.value,
                code=payload.code,
            )
            user = await repository.get_by_phone(country, phone, for_update=True)
            identifier_hash = self._hashing.identifier_hash(destination)
            if not verification.valid or user is None:
                self._record_attempt(
                    repository=repository,
                    user=user,
                    identifier_hash=identifier_hash,
                    success=False,
                    failure_code="OTP_INVALID",
                    context=context,
                )
                pending_error = InvalidCredentialsError()
            else:
                try:
                    AccountAccessPolicy.ensure_login_allowed(
                        account_access_state(user),
                        verified_channel=OTPChannel.SMS.value,
                    )
                except AuthenticationError:
                    self._record_attempt(
                        repository=repository,
                        user=user,
                        identifier_hash=identifier_hash,
                        success=False,
                        failure_code="ACCOUNT_NOT_AVAILABLE",
                        context=context,
                    )
                    pending_error = InvalidCredentialsError()
                else:
                    repository.reset_failed_login_count(user)
                    user.last_login_at = utc_now()
                    self._record_attempt(
                        repository=repository,
                        user=user,
                        identifier_hash=identifier_hash,
                        success=True,
                        failure_code=None,
                        context=context,
                    )
                    result = await self._issue_tokens(
                        user=user,
                        repository=repository,
                        context=context,
                        auth_method="otp",
                    )
        # Preserve failed-attempt audit mutations before returning a uniform
        # credential error to the client.
        if pending_error is not None:
            raise pending_error
        assert result is not None
        return result


__all__ = ["PasswordLoginService", "PhoneOtpLoginService"]
