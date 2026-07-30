"""File: app/common/exceptions.py

Purpose:
Defines framework-independent application exceptions with client-safe codes,
messages, and optional details.

Dependency flow:
Domain/service/infrastructure failure
-> AppError subtype
-> propagation without HTTP coupling
-> centralized API exception handler
-> canonical error response

Exceptions in this module carry safe, machine-readable information only. They
must not contain SQL text, connection strings, access tokens, stack traces,
patient data, or raw third-party responses. HTTP translation lives in the API
layer so domain and application code remain transport independent.
"""

from __future__ import annotations

from typing import Any, ClassVar


class AppError(Exception):
    """Base class for expected application failures.

    Args:
        message: Client-safe error message.
        details: Optional client-safe structured context.
        code: Optional override for the stable machine-readable error code.
    """

    default_code: ClassVar[str] = "APPLICATION_ERROR"
    default_message: ClassVar[str] = "The operation could not be completed."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: Any | None = None,
        code: str | None = None,
    ) -> None:
        safe_message = (message or self.default_message).strip()
        if not safe_message:
            safe_message = self.default_message
        super().__init__(safe_message)
        self.message = safe_message
        self.details = details
        self.code = code or self.default_code


class DomainError(AppError):
    """Base class for violations of domain invariants."""

    default_code = "DOMAIN_ERROR"


class ApplicationError(AppError):
    """Base class for expected use-case orchestration failures."""

    default_code = "APPLICATION_ERROR"


class ValidationError(ApplicationError):
    """Input is structurally valid but unacceptable to the use case."""

    default_code = "VALIDATION_ERROR"
    default_message = "The supplied input is invalid."


class AuthenticationError(ApplicationError):
    """Authentication credentials are missing or invalid."""

    default_code = "AUTHENTICATION_REQUIRED"
    default_message = "Authentication is required."


class AuthorizationError(ApplicationError):
    """The authenticated principal lacks permission."""

    default_code = "PERMISSION_DENIED"
    default_message = "You do not have permission to perform this operation."


class NotFoundError(ApplicationError):
    """The requested resource does not exist or is not visible."""

    default_code = "RESOURCE_NOT_FOUND"
    default_message = "The requested resource was not found."


class ConflictError(ApplicationError):
    """The requested state transition conflicts with existing state."""

    default_code = "RESOURCE_CONFLICT"
    default_message = "The request conflicts with the current resource state."


class RateLimitError(ApplicationError):
    """The caller exceeded an allowed request quota."""

    default_code = "RATE_LIMIT_EXCEEDED"
    default_message = "Too many requests. Please retry later."

    def __init__(self, *, retry_after_seconds: int) -> None:
        super().__init__(details={"retry_after_seconds": retry_after_seconds})
        self.retry_after_seconds = retry_after_seconds


class InvalidCredentialsError(AuthenticationError):
    """Represent invalid credentials error."""

    default_code = "AUTH_INVALID_CREDENTIALS"
    default_message = "Invalid credentials."


class AccountLockedError(AuthenticationError):
    """Represent account locked error."""

    default_code = "AUTH_ACCOUNT_LOCKED"
    default_message = "The account is temporarily locked."


class AccountDisabledError(AuthenticationError):
    """Represent account disabled error."""

    default_code = "AUTH_ACCOUNT_DISABLED"
    default_message = "The account is not available."


class IdentityAlreadyExistsError(ConflictError):
    """Represent identity already exists error."""

    default_code = "AUTH_IDENTITY_ALREADY_EXISTS"
    default_message = "The identity is already registered."


class OtpExpiredError(AuthenticationError):
    """Represent otp expired error."""

    default_code = "AUTH_OTP_EXPIRED"
    default_message = "The verification code has expired."


class OtpInvalidError(AuthenticationError):
    """Represent otp invalid error."""

    default_code = "AUTH_OTP_INVALID"
    default_message = "The verification code is invalid."


class OtpAttemptsExceededError(AuthenticationError):
    """Represent otp attempts exceeded error."""

    default_code = "AUTH_OTP_ATTEMPTS_EXCEEDED"
    default_message = "The verification challenge is blocked."


class OtpAlreadyUsedError(AuthenticationError):
    """Represent otp already used error."""

    default_code = "AUTH_OTP_ALREADY_USED"
    default_message = "The verification code has already been used."


class SessionRevokedError(AuthenticationError):
    """Represent session revoked error."""

    default_code = "AUTH_SESSION_REVOKED"
    default_message = "The session is expired or revoked."


class RefreshTokenReuseError(AuthenticationError):
    """Represent refresh token reuse error."""

    default_code = "AUTH_REFRESH_TOKEN_REUSE"
    default_message = "Refresh token reuse was detected."


class InsufficientPermissionsError(AuthorizationError):
    """Represent insufficient permissions error."""

    default_code = "AUTH_INSUFFICIENT_PERMISSIONS"
    default_message = "The required permission is missing."


class OperationTimeoutError(ApplicationError):
    """A bounded operation exceeded its configured deadline."""

    default_code = "OPERATION_TIMEOUT"
    default_message = "The operation timed out."


class ExternalServiceError(ApplicationError):
    """A required external integration failed safely."""

    default_code = "EXTERNAL_SERVICE_ERROR"
    default_message = "A required external service is unavailable."


class ExternalServiceTimeoutError(ExternalServiceError):
    """An external integration exceeded its configured timeout."""

    default_code = "EXTERNAL_SERVICE_TIMEOUT"
    default_message = "A required external service timed out."


class DatabaseError(ApplicationError):
    """A persistence operation failed without exposing driver details."""

    default_code = "DATABASE_ERROR"
    default_message = "A persistence operation failed."


class InfrastructureError(AppError):
    """Base class for runtime infrastructure failures."""

    default_code = "INFRASTRUCTURE_ERROR"
    default_message = "A required infrastructure component failed."


class InfrastructureUnavailableError(InfrastructureError):
    """A required infrastructure component is not available."""

    default_code = "INFRASTRUCTURE_UNAVAILABLE"
    default_message = "A required service is temporarily unavailable."


class RateLimitBackendError(InfrastructureError):
    """Redis failed while evaluating a rate limit rule."""

    default_code = "RATE_LIMIT_BACKEND_ERROR"
    default_message = "The rate limit service is unavailable."


__all__ = [
    "AccountDisabledError",
    "AccountLockedError",
    "AppError",
    "ApplicationError",
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "DatabaseError",
    "DomainError",
    "ExternalServiceError",
    "ExternalServiceTimeoutError",
    "IdentityAlreadyExistsError",
    "InfrastructureError",
    "InfrastructureUnavailableError",
    "InsufficientPermissionsError",
    "InvalidCredentialsError",
    "NotFoundError",
    "OperationTimeoutError",
    "OtpAlreadyUsedError",
    "OtpAttemptsExceededError",
    "OtpExpiredError",
    "OtpInvalidError",
    "RateLimitBackendError",
    "RateLimitError",
    "RefreshTokenReuseError",
    "SessionRevokedError",
    "ValidationError",
]
