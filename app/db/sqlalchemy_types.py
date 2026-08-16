"""File: app/db/sqlalchemy_types.py

Purpose:
Defines UTC-normalizing SQLAlchemy datetime types and consistent audit-column
factories.

Dependency flow:
Aware application datetime
-> UTCDateTime bind conversion
-> database column
-> aware UTC result conversion
-> ORM model/service

Application timestamps originate in the timezone configured through
``AppSettings.TIMEZONE``. Before persistence, timestamps are normalized to
aware UTC values for PostgreSQL ``TIMESTAMP WITH TIME ZONE`` columns.

Values restored from the database are returned as timezone-aware UTC
datetimes. Application-facing layers can convert them using
``to_application_timezone``.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.orm import MappedColumn, mapped_column
from sqlalchemy.types import TypeDecorator

from app.utils.datetime_utils import (
    UTC,
    current_datetime,
    to_utc,
)


class UTCDateTime(TypeDecorator[datetime]):
    """Persist datetimes as aware UTC and restore aware UTC in Python.

    Incoming values must contain timezone information. Values created by the
    audit-column factories originate in the configured application timezone
    and are converted to UTC at this database boundary.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self,
        value: datetime | None,
        dialect: Dialect,
    ) -> datetime | None:
        """Normalize a timezone-aware datetime to aware UTC.

        Args:
            value: Optional timezone-aware datetime.
            dialect: Active SQLAlchemy database dialect.

        Returns:
            Aware UTC datetime suitable for database persistence, or ``None``.

        Raises:
            ValueError: If ``value`` is timezone-naive.
        """
        _ = dialect

        if value is None:
            return None

        return to_utc(value)

    def process_result_value(
        self,
        value: datetime | None,
        dialect: Dialect,
    ) -> datetime | None:
        """Restore a database datetime as timezone-aware UTC.

        PostgreSQL normally returns timezone-aware values. A naive driver value
        is treated as UTC defensively; aware values are normalized to UTC.

        Args:
            value: Optional datetime returned by the database driver.
            dialect: Active SQLAlchemy database dialect.

        Returns:
            Timezone-aware UTC datetime, or ``None``.
        """
        _ = dialect

        if value is None:
            return None

        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)

        return to_utc(value)

    @property
    def python_type(self) -> type[datetime]:
        """Return the Python value type used by SQLAlchemy."""
        return datetime


def created_at_column(
    db_column_name: str | None = None,
) -> MappedColumn[datetime]:
    """Create a non-null creation audit column.

    The timestamp originates in the configured application timezone and is
    normalized to UTC by ``UTCDateTime`` before persistence.

    Args:
        db_column_name: Optional physical database column name.

    Returns:
        Configured SQLAlchemy mapped column.
    """
    return mapped_column(
        db_column_name,
        UTCDateTime(),
        nullable=False,
        default=current_datetime,
    )


def updated_at_column(
    db_column_name: str | None = None,
) -> MappedColumn[datetime]:
    """Create a non-null update audit column.

    Creation and update timestamps originate in the configured application
    timezone and are normalized to UTC before persistence.

    Args:
        db_column_name: Optional physical database column name.

    Returns:
        Configured SQLAlchemy mapped column.
    """
    return mapped_column(
        db_column_name,
        UTCDateTime(),
        nullable=False,
        default=current_datetime,
        onupdate=current_datetime,
    )


__all__ = [
    'created_at_column',
    'updated_at_column',
    'UTCDateTime',
]
