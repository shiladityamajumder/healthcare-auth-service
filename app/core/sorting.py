"""File: app/core/sorting.py

Purpose:
Builds deterministic SQLAlchemy ordering from validated, allow-listed sort
fields and directions.

Dependency flow:
Requested sort terms
-> allow-listed column resolution
-> deterministic SQLAlchemy order clauses
-> repository Select statement
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import Select
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from app.common.exceptions import ValidationError

type SQLColumn = ColumnElement[Any] | InstrumentedAttribute[Any]
type SQLOrderExpression = UnaryExpression[Any]
type SQLSelect = Select[Any]


class SortOrder(StrEnum):
    """Supported client-visible sort directions."""

    ASC = "asc"
    DESC = "desc"


def normalize_sort_order(
    value: str | SortOrder | None,
) -> SortOrder:
    """Normalize and validate a requested sort direction.

    Args:
        value: Raw sort direction or existing ``SortOrder`` value.

    Returns:
        Normalized sort direction. Missing values default to ascending order.

    Raises:
        ValidationError: If the supplied sort direction is unsupported.
    """
    if value is None:
        return SortOrder.ASC

    if isinstance(value, SortOrder):
        return value

    normalized = value.strip().lower()

    try:
        return SortOrder(normalized)
    except ValueError as exc:
        raise ValidationError(
            "Unsupported sort direction.",
            details={
                "value": value,
                "allowed": [item.value for item in SortOrder],
            },
        ) from exc


def build_order_expression(
    *,
    column: SQLColumn,
    sort_order: str | SortOrder = SortOrder.ASC,
) -> SQLOrderExpression:
    """Create a SQLAlchemy ascending or descending expression.

    Args:
        column: Allow-listed SQLAlchemy column or expression.
        sort_order: Requested sorting direction.

    Returns:
        SQLAlchemy order expression.

    Raises:
        ValidationError: If the requested direction is unsupported.
    """
    order = normalize_sort_order(sort_order)

    if order is SortOrder.DESC:
        return column.desc()

    return column.asc()


def apply_sorting(
    statement: SQLSelect,
    *,
    sort_by: str | None,
    sort_order: str | SortOrder = SortOrder.ASC,
    allowed_fields: dict[str, SQLColumn],
    strict: bool = True,
) -> SQLSelect:
    """Apply one allow-listed sorting field.

    Args:
        statement: Base SQLAlchemy select statement.
        sort_by: Public client-visible field name.
        sort_order: Requested sorting direction.
        allowed_fields: Explicit public-field-to-column mapping.
        strict: Whether unsupported fields should raise an error.

    Returns:
        Updated or unchanged SQLAlchemy select statement.

    Raises:
        ValidationError: If the sort field or direction is unsupported in
            strict mode.
    """
    if sort_by is None:
        return statement

    normalized_field = sort_by.strip()

    if not normalized_field:
        return statement

    column = allowed_fields.get(normalized_field)

    if column is None:
        if strict:
            raise ValidationError(
                "Unsupported sort field.",
                details={
                    "field": normalized_field,
                    "allowed": sorted(allowed_fields),
                },
            )

        return statement

    return statement.order_by(
        build_order_expression(
            column=column,
            sort_order=sort_order,
        )
    )


def apply_multi_sorting(
    statement: SQLSelect,
    *,
    sorting: list[tuple[str, str | SortOrder]] | None,
    allowed_fields: dict[str, SQLColumn],
    strict: bool = True,
) -> SQLSelect:
    """Apply ordered, allow-listed multi-column sorting.

    Duplicate fields are ignored after their first occurrence so callers
    cannot accidentally produce conflicting order clauses for the same column.

    Args:
        statement: Base SQLAlchemy select statement.
        sorting: Ordered field and direction pairs.
        allowed_fields: Explicit public-field-to-column mapping.
        strict: Whether unsupported fields should raise an error.

    Returns:
        Updated or unchanged SQLAlchemy select statement.

    Raises:
        ValidationError: If a field or direction is unsupported in strict mode.
    """
    if not sorting:
        return statement

    clauses: list[SQLOrderExpression] = []
    seen_fields: set[str] = set()

    for raw_field, direction in sorting:
        field = raw_field.strip()

        if not field or field in seen_fields:
            continue

        seen_fields.add(field)
        column = allowed_fields.get(field)

        if column is None:
            if strict:
                raise ValidationError(
                    "Unsupported sort field.",
                    details={
                        "field": field,
                        "allowed": sorted(allowed_fields),
                    },
                )

            continue

        clauses.append(
            build_order_expression(
                column=column,
                sort_order=direction,
            )
        )

    if not clauses:
        return statement

    return statement.order_by(*clauses)


def apply_default_sort(
    statement: SQLSelect,
    *,
    default_column: SQLColumn,
    default_order: str | SortOrder = SortOrder.DESC,
) -> SQLSelect:
    """Apply a deterministic fallback order.

    Repositories should generally include a unique secondary key when the
    primary sort column is not unique. For example, sort by ``created_at`` and
    then by ``id`` to prevent unstable pagination.

    Args:
        statement: Base SQLAlchemy select statement.
        default_column: Deterministic fallback column.
        default_order: Fallback sorting direction.

    Returns:
        SQLAlchemy statement with the fallback order applied.

    Raises:
        ValidationError: If the fallback direction is unsupported.
    """
    return statement.order_by(
        build_order_expression(
            column=default_column,
            sort_order=default_order,
        )
    )


__all__ = [
    "SQLColumn",
    "SQLOrderExpression",
    "SQLSelect",
    "SortOrder",
    "apply_default_sort",
    "apply_multi_sorting",
    "apply_sorting",
    "build_order_expression",
    "normalize_sort_order",
]
