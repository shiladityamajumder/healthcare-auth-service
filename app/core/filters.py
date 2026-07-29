"""File: `app/core/filters.py`
    Allow-listed SQLAlchemy filtering helpers for MySQL and SQL Server.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date, datetime
from typing import Any

from sqlalchemy import Select, and_, false, or_, true
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.sql.elements import ColumnElement

from app.common.exceptions import ValidationError

type SQLFilterColumn = ColumnElement[Any] | InstrumentedAttribute[Any]


def normalize_boolean(value: Any) -> bool | None:
    """Convert explicit boolean representations without using truthiness.

    Args:
        value: Raw boolean-like value.

    Returns:
        Normalized boolean value or ``None`` when the input is ``None``.

    Raises:
        ValidationError: If the value cannot be interpreted safely as a
            boolean.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int) and value in (0, 1):
        return bool(value)

    if isinstance(value, bytes):
        if value == b"\x01":
            return True

        if value == b"\x00":
            return False

    if isinstance(value, str):
        normalized = value.strip().casefold()

        if normalized in {"1", "true", "yes", "y", "on"}:
            return True

        if normalized in {"0", "false", "no", "n", "off"}:
            return False

    raise ValidationError(
        "Invalid boolean value.",
        details={
            "value_type": type(value).__name__,
        },
    )


def build_true_condition(
    column: SQLFilterColumn,
) -> ColumnElement[bool]:
    """Build a dialect-aware true comparison through SQLAlchemy.

    Args:
        column: SQLAlchemy boolean-compatible column.

    Returns:
        SQLAlchemy boolean expression.
    """
    return column == true()


def build_false_condition(
    column: SQLFilterColumn,
    *,
    include_null: bool = False,
) -> ColumnElement[bool]:
    """Build a false comparison, optionally treating null as false.

    Args:
        column: SQLAlchemy boolean-compatible column.
        include_null: Whether SQL ``NULL`` values should also match.

    Returns:
        SQLAlchemy boolean expression.
    """
    condition = column == false()

    if include_null:
        return or_(
            condition,
            column.is_(None),
        )

    return condition


def _escape_like(value: str) -> str:
    """Escape wildcard characters used by SQL ``LIKE`` expressions.

    Args:
        value: Raw user-provided search value.

    Returns:
        Escaped search value.
    """
    return (
        value.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def apply_text_search(
    statement: Select[Any],
    *,
    search: str | None,
    columns: Sequence[SQLFilterColumn],
    min_length: int = 2,
    max_length: int = 128,
) -> Select[Any]:
    """Apply escaped case-insensitive contains search to explicit columns.

    Args:
        statement: Base SQLAlchemy select statement.
        search: Optional search term.
        columns: Explicitly allow-listed searchable columns.
        min_length: Minimum accepted search length.
        max_length: Maximum accepted search length.

    Returns:
        Updated SQLAlchemy select statement.

    Raises:
        ValidationError: If the normalized search length is outside the
            permitted range.
    """
    if search is None:
        return statement

    normalized = search.strip()

    if not normalized:
        return statement

    if len(normalized) < min_length or len(normalized) > max_length:
        raise ValidationError(
            "Search length is outside the allowed range.",
            details={
                "min_length": min_length,
                "max_length": max_length,
            },
        )

    escaped = _escape_like(normalized)

    conditions = [
        column.ilike(
            f"%{escaped}%",
            escape="\\",
        )
        for column in columns
    ]

    if not conditions:
        return statement

    return statement.where(or_(*conditions))


def apply_prefix_search(
    statement: Select[Any],
    *,
    search: str | None,
    columns: Sequence[SQLFilterColumn],
    min_length: int = 1,
    max_length: int = 128,
) -> Select[Any]:
    """Apply escaped case-insensitive prefix search to explicit columns.

    Args:
        statement: Base SQLAlchemy select statement.
        search: Optional prefix search term.
        columns: Explicitly allow-listed searchable columns.
        min_length: Minimum accepted search length.
        max_length: Maximum accepted search length.

    Returns:
        Updated SQLAlchemy select statement.

    Raises:
        ValidationError: If the normalized search length is outside the
            permitted range.
    """
    if search is None:
        return statement

    normalized = search.strip()

    if not normalized:
        return statement

    if len(normalized) < min_length or len(normalized) > max_length:
        raise ValidationError(
            "Search length is outside the allowed range.",
            details={
                "min_length": min_length,
                "max_length": max_length,
            },
        )

    escaped = _escape_like(normalized)

    conditions = [
        column.ilike(
            f"{escaped}%",
            escape="\\",
        )
        for column in columns
    ]

    if not conditions:
        return statement

    return statement.where(or_(*conditions))


def apply_exact_filter(
    statement: Select[Any],
    *,
    column: SQLFilterColumn,
    value: Any,
) -> Select[Any]:
    """Apply equality filtering when a value is present.

    Args:
        statement: Base SQLAlchemy select statement.
        column: Explicitly selected database column.
        value: Value to compare.

    Returns:
        Updated or unchanged SQLAlchemy select statement.
    """
    if value is None:
        return statement

    return statement.where(column == value)


def apply_boolean_filter(
    statement: Select[Any],
    *,
    column: SQLFilterColumn,
    value: Any,
    include_null_as_false: bool = False,
) -> Select[Any]:
    """Normalize and apply a boolean filter.

    Args:
        statement: Base SQLAlchemy select statement.
        column: Boolean-compatible database column.
        value: Raw boolean-like value.
        include_null_as_false: Whether SQL ``NULL`` should match false values.

    Returns:
        Updated or unchanged SQLAlchemy select statement.

    Raises:
        ValidationError: If the value cannot be normalized as a boolean.
    """
    normalized = normalize_boolean(value)

    if normalized is None:
        return statement

    condition = (
        build_true_condition(column)
        if normalized
        else build_false_condition(
            column,
            include_null=include_null_as_false,
        )
    )

    return statement.where(condition)


def apply_in_filter(
    statement: Select[Any],
    *,
    column: SQLFilterColumn,
    values: Sequence[Any] | None,
    max_values: int = 100,
) -> Select[Any]:
    """Apply a bounded SQL ``IN`` predicate.

    Args:
        statement: Base SQLAlchemy select statement.
        column: Explicitly selected database column.
        values: Sequence of allowed values.
        max_values: Maximum number of accepted values.

    Returns:
        Updated or unchanged SQLAlchemy select statement.

    Raises:
        ValidationError: If too many filter values are supplied.
    """
    if not values:
        return statement

    if len(values) > max_values:
        raise ValidationError(
            "Too many values were supplied for a filter.",
            details={
                "max_values": max_values,
            },
        )

    return statement.where(
        column.in_(list(values)),
    )


def apply_date_range_filter(
    statement: Select[Any],
    *,
    column: SQLFilterColumn,
    start_date: date | datetime | None = None,
    end_date: date | datetime | None = None,
) -> Select[Any]:
    """Apply inclusive temporal bounds and reject reversed ranges.

    Args:
        statement: Base SQLAlchemy select statement.
        column: Date or datetime database column.
        start_date: Optional inclusive lower bound.
        end_date: Optional inclusive upper bound.

    Returns:
        Updated SQLAlchemy select statement.

    Raises:
        ValidationError: If the start value is after the end value.
    """
    if (
        start_date is not None
        and end_date is not None
        and start_date > end_date
    ):
        raise ValidationError(
            "start_date must not be after end_date"
        )

    if start_date is not None:
        statement = statement.where(
            column >= start_date,
        )

    if end_date is not None:
        statement = statement.where(
            column <= end_date,
        )

    return statement


def apply_dynamic_filters(
    statement: Select[Any],
    *,
    filters: dict[str, Any] | None,
    allowed_filters: dict[str, SQLFilterColumn],
    boolean_fields: set[str] | None = None,
    max_in_values: int = 100,
    strict: bool = True,
) -> Select[Any]:
    """Apply allow-listed exact, boolean, and bounded list filters.

    Args:
        statement: Base SQLAlchemy select statement.
        filters: Raw external filter mapping.
        allowed_filters: Explicit public-field-to-column mapping.
        boolean_fields: Fields requiring boolean normalization.
        max_in_values: Maximum number of accepted values in list filters.
        strict: Whether unsupported fields should raise an error.

    Returns:
        Updated or unchanged SQLAlchemy select statement.

    Raises:
        ValidationError: If an unsupported field is supplied in strict mode,
            a boolean value is invalid, or a list filter exceeds the configured
            maximum.
    """
    if not filters:
        return statement

    normalized_boolean_fields = boolean_fields or set()
    conditions: list[ColumnElement[bool]] = []

    for field, value in filters.items():
        column = allowed_filters.get(field)

        if column is None:
            if strict:
                raise ValidationError(
                    "Unsupported filter field.",
                    details={
                        "field": field,
                        "allowed": sorted(allowed_filters),
                    },
                )

            continue

        if value is None:
            continue

        if field in normalized_boolean_fields:
            normalized = normalize_boolean(value)

            if normalized is None:
                continue

            condition = (
                build_true_condition(column)
                if normalized
                else build_false_condition(column)
            )

            conditions.append(condition)
            continue

        if isinstance(value, Sequence) and not isinstance(
            value,
            (
                str,
                bytes,
                bytearray,
            ),
        ):
            if not value:
                continue

            if len(value) > max_in_values:
                raise ValidationError(
                    "Too many values were supplied for a filter.",
                    details={
                        "field": field,
                        "max_values": max_in_values,
                    },
                )

            conditions.append(
                column.in_(list(value)),
            )
            continue

        conditions.append(
            column == value,
        )

    if not conditions:
        return statement

    return statement.where(
        and_(*conditions),
    )


__all__ = [
    "SQLFilterColumn",
    "apply_boolean_filter",
    "apply_date_range_filter",
    "apply_dynamic_filters",
    "apply_exact_filter",
    "apply_in_filter",
    "apply_prefix_search",
    "apply_text_search",
    "build_false_condition",
    "build_true_condition",
    "normalize_boolean",
]
