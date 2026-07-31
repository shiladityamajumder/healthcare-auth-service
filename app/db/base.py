"""File: app/db/base.py

Purpose:
Defines the SQLAlchemy declarative base and reusable audit/soft-delete column
mixins for externally migrated tables.

Dependency flow:
ORM model declaration
-> declarative base and mixin columns
-> SQLAlchemy mapping metadata
-> repository persistence

The migration service owns DDL. This module intentionally does not register
schema-creation hooks and the API never calls ``metadata.create_all``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, MetaData, false, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column


def _schema_token(_constraint: Any, table: Any) -> str:
    return str(table.schema or "public")


NAMING_CONVENTION: dict[str, Any] = {
    "schema_token": _schema_token,
    "ix": "ix_%(schema_token)s_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(schema_token)s_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(schema_token)s_%(table_name)s_%(constraint_name)s",
    "fk": ("fk_%(schema_token)s_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s"),
    "pk": "pk_%(schema_token)s_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )


class CreatedAtMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class TimestampMixin(CreatedAtMixin):
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class ActorAuditMixin:
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class SoftDeleteMixin:
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=false(),
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class VersionedMixin:
    row_version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default=text("1"),
    )

    @declared_attr.directive
    def __mapper_args__(cls) -> dict[str, Any]:
        return {
            "version_id_col": cls.row_version,
            "version_id_generator": lambda current: (current or 0) + 1,
        }


class AuditMixin(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    ActorAuditMixin,
    SoftDeleteMixin,
    VersionedMixin,
    Base,
):
    __abstract__ = True


class RecordMixin(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    ActorAuditMixin,
    VersionedMixin,
    Base,
):
    __abstract__ = True


class ImmutableRecordMixin(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __abstract__ = True


__all__ = [
    "NAMING_CONVENTION",
    "ActorAuditMixin",
    "AuditMixin",
    "Base",
    "CreatedAtMixin",
    "ImmutableRecordMixin",
    "RecordMixin",
    "SoftDeleteMixin",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "VersionedMixin",
]
