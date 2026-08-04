"""File: app/models/common.py

Purpose:
Provides shared SQLAlchemy enum-column mappings for externally managed models.

Dependency flow:
Persisted StrEnum type
-> enum_column()
-> VARCHAR-backed SQLAlchemy enum with a CHECK constraint
-> externally managed PostgreSQL column

The healthcare database stores identity status fields as VARCHAR-backed enums,
not native PostgreSQL enum types. This mapping must remain aligned with the
database schema maintained by the healthcare_db repository.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Enum as SAEnum


def enum_column[EnumT: StrEnum](
    enum_type: type[EnumT],
    *,
    name: str | None = None,
) -> SAEnum:
    """Map a string enum exactly as the healthcare database defines it."""

    max_length = max(len(member.value) for member in enum_type)

    return SAEnum(
        enum_type,
        name=name or enum_type.__name__.lower(),
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda enum_class: [member.value for member in enum_class],
        length=max(16, max_length),
    )


__all__ = ["enum_column"]
