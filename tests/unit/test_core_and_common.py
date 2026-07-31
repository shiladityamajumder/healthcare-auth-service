"""File: tests/unit/test_core_and_common.py

Purpose:
Verifies canonical responses/exceptions, pagination/filter/sort helpers,
bounded execution, and trace-context parsing.

Dependency flow:
Test input
-> common contract or core utility
-> result/exception
-> behavioral assertion
"""

from __future__ import annotations

import asyncio
import json

import pytest
from app.common.exceptions import (
    ConflictError,
    OperationTimeoutError,
    ValidationError,
)
from app.common.response import APIResponse, PaginationMeta
from app.core.execution import execute_operation
from app.core.filters import apply_text_search
from app.core.pagination import PaginationParams, build_pagination_meta
from app.core.sorting import SortOrder, apply_sorting
from app.models.identity import Users
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

pytestmark = pytest.mark.unit


def test_application_exception_contract() -> None:
    error = ConflictError(
        "Duplicate record.",
        details={"field": "name"},
    )

    assert str(error) == "Duplicate record."
    assert error.message == "Duplicate record."
    assert error.code == "RESOURCE_CONFLICT"
    assert error.details == {"field": "name"}


def test_success_response_contract() -> None:
    response = APIResponse.success(
        data={"id": 10},
        pagination=PaginationMeta(
            total_count=25,
            limit=10,
            offset=0,
            has_next=True,
        ),
    )

    body = json.loads(response.body)

    assert response.status_code == 200
    assert body["success"] is True
    assert body["data"] == {"id": 10}
    assert body["error"] is None
    assert body["meta"]["pagination"] == {
        "total_count": 25,
        "limit": 10,
        "offset": 0,
        "has_next": True,
    }


def test_error_response_contract() -> None:
    response = APIResponse.error(
        error_code="RESOURCE_CONFLICT",
        message="Duplicate record.",
        status_code=409,
        details={"field": "name"},
    )

    body = json.loads(response.body)

    assert response.status_code == 409
    assert body["success"] is False
    assert body["data"] is None
    assert body["error"]["code"] == "RESOURCE_CONFLICT"
    assert response.headers["Cache-Control"] == "no-store"


def test_pagination_validation_and_metadata() -> None:
    params = PaginationParams(limit=20, offset=40)
    meta = build_pagination_meta(
        total_count=61,
        params=params,
    )

    assert meta.has_next is True
    assert meta.limit == 20
    assert meta.offset == 40

    with pytest.raises(PydanticValidationError):
        PaginationParams(limit=0)

    with pytest.raises(ValueError):
        build_pagination_meta(
            total_count=-1,
            params=params,
        )


def test_text_search_escapes_sql_wildcards() -> None:
    statement = apply_text_search(
        select(Users.id),
        search=r"50%_off",
        columns=[Users.email],
        min_length=2,
        max_length=128,
    )

    compiled = statement.compile(
        dialect=postgresql.dialect(),
    )

    assert any(
        value == r"%50\%\_off%"
        for value in compiled.params.values()
    )


def test_sorting_rejects_non_allow_listed_field() -> None:
    statement = select(Users.id)

    with pytest.raises(ValidationError):
        apply_sorting(
            statement,
            sort_by="password",
            sort_order=SortOrder.ASC,
            allowed_fields={
                "id": Users.id,
            },
        )


@pytest.mark.asyncio
async def test_execute_operation_returns_result() -> None:
    async def operation() -> int:
        return 42

    result = await execute_operation(
        operation="test.success",
        layer="unit-test",
        context={"safe": True},
        func=operation,
    )

    assert result == 42


@pytest.mark.asyncio
async def test_execute_operation_translates_timeout() -> None:
    async def operation() -> None:
        await asyncio.sleep(0.05)

    with pytest.raises(OperationTimeoutError):
        await execute_operation(
            operation="test.timeout",
            timeout_seconds=0.001,
            func=operation,
        )


@pytest.mark.asyncio
async def test_execute_operation_preserves_unexpected_error() -> None:
    class ExpectedFailure(RuntimeError):
        pass

    async def operation() -> None:
        raise ExpectedFailure("boom")

    with pytest.raises(ExpectedFailure, match="boom"):
        await execute_operation(
            operation="test.failure",
            func=operation,
        )


def test_traceparent_extracts_nonzero_trace_identifier() -> None:
    """Accept a valid W3C traceparent and reject an all-zero trace identifier."""
    from app.core.middleware import _extract_trace_id

    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    assert _extract_trace_id(f"00-{trace_id}-00f067aa0ba902b7-01") == trace_id
    assert _extract_trace_id("00-00000000000000000000000000000000-00f067aa0ba902b7-01") is None
    assert _extract_trace_id("invalid") is None
