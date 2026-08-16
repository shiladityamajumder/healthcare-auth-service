"""Read-only ORM mappings for platform resources consumed by auth.

The healthcare database service owns migrations for these tables. Auth maps
only the canonical file-object table because authenticated profile responses
must resolve public avatar CDN URLs without calling another service.

Storage keys, encryption references, private files, and non-final file states
are never included in auth API responses.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin
from app.models.common import enum_column
from app.models.enums import FileAccessType, FileObjectStatus, MalwareScanStatus

IDENTITY_AVATAR_OWNER_TYPE = "identity.user_profile.avatar"


class FileObjects(AuditMixin):
    """Map canonical file metadata owned and migrated by healthcare_db.

    Auth treats this entity as read-only. Its only supported use is validating
    an avatar reference and resolving an already-finalized public CDN URL.
    """

    __tablename__ = "file_objects"
    __table_args__ = (
        UniqueConstraint("bucket", "object_key", name="file_bucket_object_key"),
        Index("ix_platform_file_objects_owner", "owner_type", "owner_id"),
        Index("ix_platform_file_objects_sha256", "sha256"),
        Index("ix_platform_file_objects_status", "status", "created_at"),
        Index("ix_platform_file_objects_uploaded_by", "uploaded_by_user_id"),
        CheckConstraint("expected_size_bytes > 0", name="expected_size_positive"),
        CheckConstraint("size_bytes IS NULL OR size_bytes > 0", name="size_positive"),
        CheckConstraint(
            "sha256 IS NULL OR char_length(sha256) = 64",
            name="sha256_length",
        ),
        CheckConstraint(
            "access_type <> 'private' OR public_url IS NULL",
            name="private_has_no_public_url",
        ),
        CheckConstraint(
            "status <> 'available' OR "
            "(size_bytes IS NOT NULL AND sha256 IS NOT NULL "
            "AND malware_scan_status = 'clean')",
            name="available_has_safe_final_metadata",
        ),
        {"schema": "platform"},
    )

    storage_provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default="s3",
    )
    bucket: Mapped[str] = mapped_column(String(128), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    owner_type: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    uploaded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="SET NULL"),
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    etag: Mapped[str | None] = mapped_column(String(255))
    storage_version_id: Mapped[str | None] = mapped_column(String(255))
    encryption_key_ref: Mapped[str | None] = mapped_column(String(255))
    classification: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default="internal",
    )
    access_type: Mapped[FileAccessType] = mapped_column(
        enum_column(FileAccessType),
        nullable=False,
        server_default=FileAccessType.PRIVATE.value,
    )
    status: Mapped[FileObjectStatus] = mapped_column(
        enum_column(FileObjectStatus),
        nullable=False,
        server_default=FileObjectStatus.PENDING_UPLOAD.value,
    )
    malware_scan_status: Mapped[MalwareScanStatus] = mapped_column(
        enum_column(MalwareScanStatus),
        nullable=False,
        server_default=MalwareScanStatus.PENDING.value,
    )
    public_url: Mapped[str | None] = mapped_column(String(2048))
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any] | list[Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )


__all__ = ["FileObjects", "IDENTITY_AVATAR_OWNER_TYPE"]
