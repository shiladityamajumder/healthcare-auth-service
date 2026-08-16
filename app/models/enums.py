"""File: app/models/enums.py

Purpose:
Defines auth-consumed string enums that must remain aligned with persisted
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


class FileAccessType(StrEnum):
    """How a file object may be delivered to an API client."""

    PUBLIC = "public"
    PRIVATE = "private"


class FileObjectStatus(StrEnum):
    """Lifecycle states persisted by the file service."""

    PENDING_UPLOAD = "pending_upload"
    UPLOADED = "uploaded"
    SCANNING = "scanning"
    AVAILABLE = "available"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    DELETED = "deleted"


class MalwareScanStatus(StrEnum):
    """Malware scan states persisted for a file object."""

    PENDING = "pending"
    SCANNING = "scanning"
    CLEAN = "clean"
    INFECTED = "infected"
    FAILED = "failed"


class OTPChannel(StrEnum):
    """Delivery channels supported for one-time passwords."""

    EMAIL = "email"
    SMS = "sms"


class OTPPurpose(StrEnum):
    """Supported purposes for issuing and validating OTP challenges.

    Purpose-specific values distinguish workflows and delivery channels so
    challenges cannot be reused across unrelated authentication operations.

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

class MFAFactorType(StrEnum):
    """Multi-factor authentication methods supported by the service."""

    TOTP = "totp"
    RECOVERY_CODES = "recovery_codes"


__all__ = [
    'ActiveStatus',
    'FileAccessType',
    'FileObjectStatus',
    'MalwareScanStatus',
    'MFAFactorType',
    'OTPChannel',
    'OTPPurpose',
    'UserStatus',
]
