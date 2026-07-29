"""SQLAlchemy mappings for the externally migrated identity schema."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    false,
    func,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, ImmutableRecordMixin, RecordMixin
from app.models.common import enum_column
from app.models.enums import ActiveStatus, UserStatus


class Users(RecordMixin):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email_normalized", name="users_email_normalized"),
        Index(
            "uq_identity_users_phone_present",
            "phone_country_code",
            "phone_number",
            unique=True,
            postgresql_where=text(
                "phone_country_code IS NOT NULL AND phone_number IS NOT NULL"
            ),
        ),
        CheckConstraint(
            "email_normalized IS NOT NULL OR phone_number IS NOT NULL",
            name="contact_required",
        ),
        CheckConstraint(
            "(phone_country_code IS NULL AND phone_number IS NULL) OR "
            "(phone_country_code IS NOT NULL AND phone_number IS NOT NULL)",
            name="phone_pair_complete",
        ),
        CheckConstraint("failed_login_count >= 0", name="failed_login_nonnegative"),
        Index("ix_identity_users_status", "status"),
        Index("ix_identity_users_last_login_at", "last_login_at"),
        {"schema": "identity"},
    )

    email: Mapped[str | None] = mapped_column(String(320))
    email_normalized: Mapped[str | None] = mapped_column(String(320))
    phone_country_code: Mapped[str | None] = mapped_column(String(8))
    phone_number: Mapped[str | None] = mapped_column(String(32))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[UserStatus] = mapped_column(
        enum_column(UserStatus),
        nullable=False,
        server_default=UserStatus.ACTIVE.value,
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    phone_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_login_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0"),
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    preferred_locale: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default="en-IN",
    )
    timezone: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        server_default="Asia/Kolkata",
    )
    terms_version: Mapped[str | None] = mapped_column(String(32))
    privacy_version: Mapped[str | None] = mapped_column(String(32))
    account_closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Roles(AuditMixin):
    __tablename__ = "roles"
    __table_args__ = (
        Index(
            "uq_identity_roles_code_active",
            "code",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        {"schema": "identity"},
    )

    code: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())


class Permissions(AuditMixin):
    __tablename__ = "permissions"
    __table_args__ = (
        Index(
            "uq_identity_permissions_code_active",
            "code",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index("ix_identity_permissions_resource_action", "resource", "action"),
        {"schema": "identity"},
    )

    code: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class UserRoles(RecordMixin):
    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "role_id",
            "scope_type",
            "scope_id",
            name="user_role_scope",
            postgresql_nulls_not_distinct=True,
        ),
        CheckConstraint(
            "valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from",
            name="valid_window",
        ),
        Index("ix_identity_user_roles_user_id", "user_id"),
        Index("ix_identity_user_roles_role_id", "role_id"),
        Index("ix_identity_user_roles_scope", "scope_type", "scope_id"),
        {"schema": "identity"},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope_type: Mapped[str | None] = mapped_column(String(32))
    scope_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())


class RolePermissions(RecordMixin):
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="role_permission"),
        Index("ix_identity_role_permissions_role_id", "role_id"),
        {"schema": "identity"},
    )

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.permissions.id", ondelete="CASCADE"),
        nullable=False,
    )


class Sessions(RecordMixin):
    __tablename__ = "sessions"
    __table_args__ = (
        UniqueConstraint("refresh_token_hash", name="sessions_refresh_token_hash"),
        Index("ix_identity_sessions_user_id", "user_id"),
        Index("ix_identity_sessions_device_id", "device_id"),
        Index("ix_identity_sessions_expires_at", "expires_at"),
        CheckConstraint("expires_at > created_at", name="expires_after_created"),
        {"schema": "identity"},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    refresh_token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    token_family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    device_id: Mapped[str | None] = mapped_column(String(255))
    device_type: Mapped[str | None] = mapped_column(String(32))
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(255))


class OtpChallenges(RecordMixin):
    __tablename__ = "otp_challenges"
    __table_args__ = (
        Index("ix_identity_otp_challenges_destination", "destination_hash", "purpose"),
        Index("ix_identity_otp_challenges_expires_at", "expires_at"),
        CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
        CheckConstraint("max_attempts > 0", name="max_attempts_positive"),
        CheckConstraint("attempts <= max_attempts", name="attempts_within_limit"),
        {"schema": "identity"},
    )

    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    destination_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    otp_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("5"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    blocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MfaFactors(RecordMixin):
    __tablename__ = "mfa_factors"
    __table_args__ = (
        UniqueConstraint("user_id", "factor_type", "label", name="user_mfa_factor"),
        Index("ix_identity_mfa_factors_user_id", "user_id"),
        {"schema": "identity"},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    factor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(64), nullable=False, server_default="default")
    secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    destination_masked: Mapped[str | None] = mapped_column(String(255))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TrustedDevices(RecordMixin):
    __tablename__ = "trusted_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "device_fingerprint_hash", name="user_trusted_device"),
        Index("ix_identity_trusted_devices_user_id", "user_id"),
        {"schema": "identity"},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_fingerprint_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    device_name: Mapped[str | None] = mapped_column(String(128))
    trusted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LoginAttempts(ImmutableRecordMixin):
    __tablename__ = "login_attempts"
    __table_args__ = (
        Index("ix_identity_login_attempts_user_id_created_at", "user_id", "created_at"),
        Index("ix_identity_login_attempts_ip_created_at", "ip_address", "created_at"),
        {"schema": "identity"},
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="SET NULL"),
    )
    login_identifier_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class PasswordHistory(ImmutableRecordMixin):
    __tablename__ = "password_history"
    __table_args__ = (
        Index("ix_identity_password_history_user_id_created_at", "user_id", "created_at"),
        {"schema": "identity"},
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)


class ApiClients(AuditMixin):
    __tablename__ = "api_clients"
    __table_args__ = (
        Index(
            "uq_identity_api_clients_key_active",
            "client_key",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        {"schema": "identity"},
    )

    client_name: Mapped[str] = mapped_column(String(128), nullable=False)
    client_key: Mapped[str] = mapped_column(String(128), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    allowed_scopes: Mapped[list[Any] | dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'[]'::jsonb"),
    )
    allowed_cidrs: Mapped[list[Any] | dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'[]'::jsonb"),
    )
    status: Mapped[ActiveStatus] = mapped_column(
        enum_column(ActiveStatus),
        nullable=False,
        server_default=ActiveStatus.ACTIVE.value,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    secret_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ApiClientSecrets(RecordMixin):
    __tablename__ = "api_client_secrets"
    __table_args__ = (
        Index("ix_identity_api_client_secrets_client_id", "api_client_id"),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="expiry_after_created",
        ),
        {"schema": "identity"},
    )

    api_client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.api_clients.id", ondelete="CASCADE"),
        nullable=False,
    )
    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


__all__ = [
    "ApiClientSecrets",
    "ApiClients",
    "LoginAttempts",
    "MfaFactors",
    "OtpChallenges",
    "PasswordHistory",
    "Permissions",
    "RolePermissions",
    "Roles",
    "Sessions",
    "TrustedDevices",
    "UserRoles",
    "Users",
]
