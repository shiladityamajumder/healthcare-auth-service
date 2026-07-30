"""File: app/modules/registration/service.py
Registration application services for email/password and phone/OTP flows."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy.exc import IntegrityError

from app.auth.authorization.policies import OtpVerificationPolicy
from app.auth.identity.normalization import normalize_email, normalize_phone, phone_destination
from app.auth.identity.presentation import public_user_data
from app.auth.request_context.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.auth.security.passwords import PasswordManager
from app.auth.security.tokens import TokenManager
from app.auth.workflows.notifications import AuthNotificationGateway, NotificationDispatcher
from app.auth.workflows.otp import IssuedOTP, OTPService
from app.auth.workflows.session_tokens import (
    DeviceMetadataPort,
    IssuedSessionTokens,
    SessionTokenIssuer,
)
from app.common.exceptions import (
    IdentityAlreadyExistsError,
    InfrastructureUnavailableError,
    ValidationError,
)
from app.core.config import AppSettings
from app.core.logging import get_logger
from app.db.uow import SQLAlchemyUnitOfWork
from app.models.enums import OTPChannel, OTPPurpose, UserStatus
from app.models.identity import Roles, Users
from app.modules.registration.repositories import RegistrationRepository
from app.modules.registration.schemas import (
    EmailPasswordRegistrationRequest,
    OtpChallengeResponse,
    PhoneOtpRegistrationRequest,
    PhoneOtpRegistrationVerifyRequest,
    RegistrationResponse,
    TokenPairResponse,
    UserResponse,
)
from app.utils.datetime_utils import utc_now

logger = get_logger(__name__)


def _user_response(
    user: Users,
    *,
    roles: Sequence[str],
    permissions: Sequence[str],
) -> UserResponse:
    """Map a persisted user and its effective authorization to the API DTO."""
    return UserResponse.model_validate(
        public_user_data(user, roles=roles, permissions=permissions)
    )


def _token_response(
    issued: IssuedSessionTokens,
    *,
    user: UserResponse,
) -> TokenPairResponse:
    """Combine raw issued tokens with the public user representation."""
    return TokenPairResponse(
        access_token=issued.access_token,
        refresh_token=issued.refresh_token,
        access_expires_at=issued.access_expires_at,
        refresh_expires_at=issued.refresh_expires_at,
        user=user,
    )


class _OtpResponseFactory:
    """Build safe OTP responses without leaking production verification codes."""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings

    def create(self, issued: IssuedOTP) -> OtpChallengeResponse:
        """Map an issued challenge to the public response contract."""
        return OtpChallengeResponse(
            challenge_id=issued.challenge.id,
            expires_at=issued.challenge.expires_at,
            retry_after_seconds=self._settings.OTP_RESEND_COOLDOWN_SECONDS,
            development_otp=self.development_code(issued.code),
        )

    def development_code(self, code: str) -> str | None:
        """Expose the OTP only in explicitly enabled non-production environments."""
        if not self._settings.OTP_DEV_EXPOSE_CODE:
            return None
        if self._settings.ENVIRONMENT.value not in {
            "local",
            "development",
            "testing",
        }:
            return None
        return code


class _RegistrationWriter:
    """Create a user and its initial RBAC state inside one transaction."""

    def __init__(
        self,
        *,
        uow: SQLAlchemyUnitOfWork,
        settings: AppSettings,
        passwords: PasswordManager,
    ) -> None:
        self._uow = uow
        self._settings = settings
        self._passwords = passwords

    async def create(
        self,
        *,
        repository: RegistrationRepository,
        email: str | None = None,
        phone_country_code: str | None = None,
        phone_number: str | None = None,
        password: str | None = None,
        status: UserStatus,
        email_verified_at: datetime | None = None,
        phone_verified_at: datetime | None = None,
        preferred_locale: str,
        timezone: str,
        terms_version: str | None,
        privacy_version: str | None,
        requested_role_codes: list[str],
    ) -> Users:
        """Validate initial roles, hash the password, and stage account state."""
        roles = await self._registration_roles(
            repository=repository,
            requested_role_codes=requested_role_codes,
        )
        password_hash = await self._passwords.hash(password) if password else None
        user = Users(
            id=uuid.uuid4(),
            email=email,
            email_normalized=email,
            phone_country_code=phone_country_code,
            phone_number=phone_number,
            password_hash=password_hash,
            status=status,
            email_verified_at=email_verified_at,
            phone_verified_at=phone_verified_at,
            preferred_locale=preferred_locale,
            timezone=timezone,
            terms_version=terms_version,
            privacy_version=privacy_version,
        )
        repository.add_user(user)
        if password_hash:
            repository.add_password_history(user_id=user.id, password_hash=password_hash)
        repository.assign_roles(user_id=user.id, roles=roles)
        await self._uow.flush()
        return user

    async def _registration_roles(
        self,
        *,
        repository: RegistrationRepository,
        requested_role_codes: list[str],
    ) -> list[Roles]:
        """Resolve and authorize all initial roles with one database query.

        Public registration may select multiple active custom roles. System
        roles are security-managed and cannot be self-assigned, except for the
        configured default role that every new account receives.
        """
        default_code = self._settings.DEFAULT_ROLE_CODE
        role_codes = list(dict.fromkeys([default_code, *requested_role_codes]))
        available = await repository.active_roles_by_code(role_codes)

        default_role = available.get(default_code)
        if default_role is None and self._settings.DEFAULT_ROLE_REQUIRED:
            raise InfrastructureUnavailableError(
                f"Required default role '{default_code}' is missing."
            )

        missing = [code for code in requested_role_codes if code not in available]
        restricted = [
            code
            for code in requested_role_codes
            if code != default_code
            and code in available
            and available[code].is_system
        ]
        unavailable = list(dict.fromkeys([*missing, *restricted]))
        if unavailable:
            raise ValidationError(
                "One or more requested roles are unavailable for registration.",
                details={"roles": unavailable},
                code="REGISTRATION_ROLE_UNAVAILABLE",
            )

        return [available[code] for code in role_codes if code in available]


class _RegistrationBase:
    """Shared dependencies and session-token behavior for registration flows."""

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
        self._otp = otp
        # The notification gateway is injected so a real email/SMS adapter can
        # be enabled later without coupling registration to an HTTP client.
        self._notification = NotificationDispatcher(notifications)
        self._otp_responses = _OtpResponseFactory(settings)
        self._issuer = SessionTokenIssuer(tokens=tokens, hashing=hashing)
        self._writer = _RegistrationWriter(
            uow=uow,
            settings=settings,
            passwords=passwords,
        )

    async def _issue_tokens(
        self,
        *,
        user: Users,
        repository: RegistrationRepository,
        context: AuthRequestContext,
        device: DeviceMetadataPort,
        auth_methods: list[str],
    ) -> TokenPairResponse:
        """Issue the first session using current roles and request metadata."""
        claims = await repository.authorization_claims(user_id=user.id, now=utc_now())
        user_dto = _user_response(
            user,
            roles=claims.roles,
            permissions=claims.permissions,
        )
        issued = self._issuer.issue(
            user_id=user.id,
            roles=claims.roles,
            permissions=claims.permissions,
            session_writer=repository,
            request_context=context,
            device=device,
            auth_methods=auth_methods,
        )
        return _token_response(issued, user=user_dto)


class EmailPasswordRegistrationService(_RegistrationBase):
    """Register an account with email and password."""

    async def register(
        self,
        payload: EmailPasswordRegistrationRequest,
        context: AuthRequestContext,
    ) -> RegistrationResponse:
        """Create an email identity, its roles, and verification challenge."""
        email = normalize_email(str(payload.email))
        self._passwords.validate_strength(payload.password, email=email)
        issued_otp: IssuedOTP | None = None
        try:
            async with self._uow:
                repository = RegistrationRepository(self._uow.session)
                if await repository.email_exists(email):
                    raise IdentityAlreadyExistsError(
                        "An account with this email address is already registered.",
                        details={"field": "email"},
                    )
                user = await self._writer.create(
                    repository=repository,
                    email=email,
                    password=payload.password,
                    status=(
                        UserStatus.PENDING_VERIFICATION
                        if self._settings.EMAIL_VERIFICATION_REQUIRED
                        else UserStatus.ACTIVE
                    ),
                    email_verified_at=(
                        None
                        if self._settings.EMAIL_VERIFICATION_REQUIRED
                        else utc_now()
                    ),
                    preferred_locale=payload.preferred_locale,
                    timezone=payload.timezone,
                    terms_version=payload.terms_version,
                    privacy_version=payload.privacy_version,
                    requested_role_codes=payload.roles,
                )
                if self._settings.EMAIL_VERIFICATION_REQUIRED:
                    issued_otp = await self._otp.issue(
                        repository=repository,
                        channel=OTPChannel.EMAIL.value,
                        destination=email,
                        purpose=OTPPurpose.VERIFY_EMAIL.value,
                    )
                    claims = await repository.authorization_claims(
                        user_id=user.id,
                        now=utc_now(),
                    )
                    result = RegistrationResponse(
                        user=_user_response(
                            user,
                            roles=claims.roles,
                            permissions=claims.permissions,
                        ),
                        verification_required=True,
                        challenge_id=issued_otp.challenge.id,
                        expires_at=issued_otp.challenge.expires_at,
                        development_otp=self._otp_responses.development_code(
                            issued_otp.code
                        ),
                    )
                else:
                    tokens = await self._issue_tokens(
                        user=user,
                        repository=repository,
                        context=context,
                        device=payload,
                        auth_methods=["password"],
                    )
                    result = RegistrationResponse(
                        user=tokens.user,
                        verification_required=False,
                        tokens=tokens,
                    )
        except IntegrityError as exc:
            # The unique database constraint closes the race between the
            # friendly existence check and insertion by concurrent requests.
            raise IdentityAlreadyExistsError(
                "An account with this email address is already registered.",
                details={"field": "email"},
            ) from exc

        # External email delivery is intentionally paused. Uncomment this
        # injected-gateway call when the notification API is connected:
        # if issued_otp is not None:
        #     await self._notification.send_otp(
        #         channel=OTPChannel.EMAIL.value,
        #         destination=email,
        #         code=issued_otp.code,
        #         purpose=OTPPurpose.VERIFY_EMAIL.value,
        #         expires_in_seconds=self._settings.OTP_TTL_SECONDS,
        #     )
        logger.info("Email registration workflow completed")
        return result


class PhoneOtpRegistrationService(_RegistrationBase):
    """Register an account through a verified phone OTP."""

    async def request(
        self,
        payload: PhoneOtpRegistrationRequest,
    ) -> OtpChallengeResponse:
        """Reject existing phones and issue a rate-bounded SMS challenge."""
        country, phone = normalize_phone(
            payload.phone_country_code,
            payload.phone_number,
        )
        destination = phone_destination(country, phone)
        async with self._uow:
            repository = RegistrationRepository(self._uow.session)
            if await repository.phone_exists(country, phone):
                raise IdentityAlreadyExistsError(
                    "An account with this country code and phone number is already registered.",
                    details={"fields": ["phone_country_code", "phone_number"]},
                )
            issued = await self._otp.issue(
                repository=repository,
                channel=OTPChannel.SMS.value,
                destination=destination,
                purpose=OTPPurpose.REGISTRATION_PHONE.value,
            )
        # External SMS delivery is intentionally paused. Uncomment this
        # injected-gateway call when the notification API is connected:
        # await self._notification.send_otp(
        #     channel=OTPChannel.SMS.value,
        #     destination=destination,
        #     code=issued.code,
        #     purpose=OTPPurpose.REGISTRATION_PHONE.value,
        #     expires_in_seconds=self._settings.OTP_TTL_SECONDS,
        # )
        return self._otp_responses.create(issued)

    async def verify(
        self,
        payload: PhoneOtpRegistrationVerifyRequest,
        context: AuthRequestContext,
    ) -> TokenPairResponse:
        """Verify the phone proof and atomically create roles and a session."""
        country, phone = normalize_phone(
            payload.phone_country_code,
            payload.phone_number,
        )
        destination = phone_destination(country, phone)
        if payload.password:
            self._passwords.validate_strength(payload.password, phone_number=phone)
        try:
            async with self._uow:
                repository = RegistrationRepository(self._uow.session)
                verification = await self._otp.verify(
                    repository=repository,
                    challenge_id=payload.challenge_id,
                    channel=OTPChannel.SMS.value,
                    destination=destination,
                    purpose={
                        OTPPurpose.REGISTRATION_PHONE.value,
                        OTPPurpose.REGISTER_MOBILE.value,
                    },
                    code=payload.code,
                )
                OtpVerificationPolicy.require_valid(verification)
                if await repository.phone_exists(country, phone):
                    raise IdentityAlreadyExistsError(
                        "An account with this country code and phone number is already registered.",
                        details={"fields": ["phone_country_code", "phone_number"]},
                    )
                user = await self._writer.create(
                    repository=repository,
                    phone_country_code=country,
                    phone_number=phone,
                    password=payload.password,
                    status=UserStatus.ACTIVE,
                    phone_verified_at=utc_now(),
                    preferred_locale=payload.preferred_locale,
                    timezone=payload.timezone,
                    terms_version=payload.terms_version,
                    privacy_version=payload.privacy_version,
                    requested_role_codes=payload.roles,
                )
                return await self._issue_tokens(
                    user=user,
                    repository=repository,
                    context=context,
                    device=payload,
                    auth_methods=["otp"],
                )
        except IntegrityError as exc:
            raise IdentityAlreadyExistsError(
                "An account with this country code and phone number is already registered.",
                details={"fields": ["phone_country_code", "phone_number"]},
            ) from exc


__all__ = [
    "EmailPasswordRegistrationService",
    "PhoneOtpRegistrationService",
]
