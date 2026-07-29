"""Identity-domain enum values aligned with the existing database contract."""

from __future__ import annotations

from enum import StrEnum


class UserStatus(StrEnum):
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    LOCKED = "locked"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class ActiveStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class OTPChannel(StrEnum):
    EMAIL = "email"
    SMS = "sms"


class OTPPurpose(StrEnum):
    REGISTRATION_EMAIL = "registration_email"
    REGISTRATION_PHONE = "registration_phone"
    LOGIN_EMAIL = "login_email"
    LOGIN_PHONE = "login_phone"
    PASSWORD_RESET_EMAIL = "password_reset_email"
    PASSWORD_RESET_PHONE = "password_reset_phone"
    VERIFY_EMAIL = "verify_email"
    VERIFY_PHONE = "verify_phone"
    MFA_LOGIN = "mfa_login"
    MFA_RECOVERY = "mfa_recovery"

    # Legacy values remain accepted during rolling deployment so already-issued
    # challenges can complete safely. New challenges use purpose-specific values.
    REGISTER_MOBILE = "register_mobile"
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"


class MFAFactorType(StrEnum):
    TOTP = "totp"
    RECOVERY_CODES = "recovery_codes"


__all__ = [
    "ActiveStatus",
    "MFAFactorType",
    "OTPChannel",
    "OTPPurpose",
    "UserStatus",
]
