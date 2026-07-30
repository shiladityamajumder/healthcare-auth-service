"""File: app/models/common.py
Shared SQLAlchemy model helpers for PostgreSQL enum columns."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy.dialects.postgresql import ENUM


def enum_column(enum_type: type[StrEnum]) -> ENUM:
    """Map an externally managed PostgreSQL enum using its string values."""
    return ENUM(
        enum_type,
        name=enum_type.__name__.replace("Status", "_status").lower(),
        schema="identity",
        native_enum=True,
        validate_strings=True,
        values_callable=lambda values: [item.value for item in values],
        create_type=False,
    )


__all__ = ["enum_column"]
