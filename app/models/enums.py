"""File: app/models/enums.py

Purpose:
Defines identity-domain string enums that must remain aligned with persisted
PostgreSQL values and API contracts.

Dependency flow:
Database/API string value
-> typed identity enum
-> ORM mapping, validation, and policy comparisons

The string values in this module may be persisted in PostgreSQL or included in
internal application contracts. Existing names and values must not be renamed
without a coordinated database migration and backward-compatibility plan.
"""

from __future__ import annotations

from enum import StrEnum


class UserStatus(StrEnum):
    """Lifecycle states supported by identity.users.status."""

    PENDING = "pending"
    ACTIVE = "active"
    LOCKED = "locked"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class ActiveStatus(StrEnum):
    """Generic active-state values used by identity-related records."""

    ACTIVE = "active"
    INACTIVE = "inactive"


class OTPChannel(StrEnum):
    """Delivery channels supported for one-time passwords."""

    EMAIL = "email"
    SMS = "sms"


class OTPPurpose(StrEnum):
    """Supported purposes for issuing and validating OTP challenges.

    Purpose-specific values distinguish workflows and delivery channels so
    challenges cannot be reused across unrelated authentication operations.

    Legacy values remain available during rolling deployments so challenges
    issued by an older application version can still complete safely. New OTP
    challenges should use the purpose-specific values whenever possible.
    """

    # Registration verification
    REGISTRATION_EMAIL = "registration_email"
    REGISTRATION_PHONE = "registration_phone"

    # Passwordless or OTP-assisted login
    LOGIN_EMAIL = "login_email"
    LOGIN_PHONE = "login_phone"

    # Password recovery
    # These are workflow identifiers, not hardcoded passwords or credentials.
    PASSWORD_RESET_EMAIL = "password_reset_email"  # noqa: S105
    PASSWORD_RESET_PHONE = "password_reset_phone"  # noqa: S105

    # Verification of contact information after registration
    VERIFY_EMAIL = "verify_email"
    VERIFY_PHONE = "verify_phone"

    # Multi-factor authentication
    MFA_LOGIN = "mfa_login"
    MFA_RECOVERY = "mfa_recovery"

    # Legacy values retained for backward compatibility with OTP challenges
    # that may already exist in the database during a rolling deployment.
    REGISTER_MOBILE = "register_mobile"
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"  # noqa: S105


class MFAFactorType(StrEnum):
    """Multi-factor authentication methods supported by the service."""

    TOTP = "totp"
    RECOVERY_CODES = "recovery_codes"


__all__ = [
    "ActiveStatus",
    "MFAFactorType",
    "OTPChannel",
    "OTPPurpose",
    "UserStatus",
]
