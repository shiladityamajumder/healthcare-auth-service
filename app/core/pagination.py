"""File: `app/core/pagination.py`
    Typed offset-pagination primitives for relational repositories.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.common.response import PaginationMeta

DEFAULT_LIMIT = 20
MAX_LIMIT = 100
MAX_OFFSET = 100_000


class PaginationParams(BaseModel):
    """Public offset-pagination request parameters.

    Large datasets should add module-specific cursor pagination instead of
    increasing ``MAX_OFFSET``. Deep offsets become progressively expensive on
    both MySQL and Microsoft SQL Server.
    """

    model_config = ConfigDict(extra="forbid")

    limit: int = Field(
        default=DEFAULT_LIMIT,
        ge=1,
        le=MAX_LIMIT,
    )
    offset: int = Field(
        default=0,
        ge=0,
        le=MAX_OFFSET,
    )


@dataclass(frozen=True, slots=True)
class PaginationResult[T]:
    """Materialized page plus stable response metadata.

    Attributes:
        items: Materialized page items.
        pagination: Public pagination metadata.
    """

    items: list[T]
    pagination: PaginationMeta


def apply_pagination[T](
    statement: Select[tuple[T]],
    *,
    params: PaginationParams,
) -> Select[tuple[T]]:
    """Apply validated limit and offset values to a statement.

    The caller must apply deterministic ordering before invoking this helper.

    Args:
        statement: SQLAlchemy select statement.
        params: Validated pagination parameters.

    Returns:
        Paginated SQLAlchemy select statement.
    """
    return statement.limit(params.limit).offset(params.offset)


def build_pagination_meta(
    *,
    total_count: int,
    params: PaginationParams,
) -> PaginationMeta:
    """Build public pagination metadata from a trusted total count.

    Args:
        total_count: Total number of matching records.
        params: Pagination parameters used for the current query.

    Returns:
        Public pagination metadata.

    Raises:
        ValueError: If ``total_count`` is negative.
    """
    if total_count < 0:
        raise ValueError("total_count cannot be negative")

    return PaginationMeta(
        total_count=total_count,
        limit=params.limit,
        offset=params.offset,
        has_next=(params.offset + params.limit) < total_count,
    )


async def paginate_scalars[T](
    *,
    session: AsyncSession,
    data_statement: Select[tuple[T]],
    count_statement: Select[tuple[int]],
    params: PaginationParams,
) -> PaginationResult[T]:
    """Execute a supplied count query and scalar data query.

    Requiring a dedicated count statement avoids incorrect counts caused by
    joins and prevents this utility from generating unexpectedly expensive
    subqueries.

    The caller must apply deterministic ordering to ``data_statement`` before
    invoking this function.

    Args:
        session: Active SQLAlchemy asynchronous session.
        data_statement: Scalar entity or value query.
        count_statement: Query returning the total matching row count.
        params: Validated pagination parameters.

    Returns:
        Materialized page and response metadata.
    """
    total_value = await session.scalar(count_statement)
    total_count = int(total_value or 0)

    result = await session.scalars(
        apply_pagination(
            data_statement,
            params=params,
        )
    )

    items = list(result.all())

    return PaginationResult(
        items=items,
        pagination=build_pagination_meta(
            total_count=total_count,
            params=params,
        ),
    )


__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "MAX_OFFSET",
    "PaginationParams",
    "PaginationResult",
    "apply_pagination",
    "build_pagination_meta",
    "paginate_scalars",
]
