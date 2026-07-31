"""File: app/common/response.py

Purpose:
Builds the canonical success/error envelope and response metadata returned to
API clients.

Dependency flow:
Route result or exception handler
-> APIResponse.success() or APIResponse.error()
-> request/correlation context and optional pagination
-> JSON-safe encoding
-> JSONResponse

This module defines the stable JSON response contract exposed to API clients.
All timestamps are generated through the shared datetime utility to preserve
the application's UTC and timezone policies.
"""

from __future__ import annotations

from typing import Any

from fastapi import status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.request_context import (
    get_api_version,
    get_correlation_id,
    get_request_id,
)
from app.utils.datetime_utils import utc_now


class PaginationMeta(BaseModel):
    """Offset-pagination metadata exposed to API clients.

    Attributes:
        total_count: Total number of matching records.
        limit: Maximum number of records returned.
        offset: Number of records skipped.
        has_next: Whether another result page is available.
    """

    model_config = ConfigDict(extra="forbid")

    total_count: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)
    has_next: bool


class ErrorBody(BaseModel):
    """Machine-readable and client-safe error information.

    Attributes:
        code: Stable application error identifier.
        message: Human-readable client-safe message.
        details: Optional structured error context.
    """

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    details: Any | None = None

    @field_validator("code", "message")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        """Normalize and reject blank error fields.

        Args:
            value: Raw error field value.

        Returns:
            Normalized non-blank value.

        Raises:
            ValueError: If the value is blank.
        """
        normalized = value.strip()

        if not normalized:
            raise ValueError("Error code and message must not be blank")

        return normalized


class ResponseMeta(BaseModel):
    """Operational metadata included in every API response.

    Attributes:
        request_id: Unique identifier for the current HTTP request.
        correlation_id: Identifier shared across related service calls.
        api_version: Public API version associated with the request.
        timestamp: UTC timestamp representing response creation time.
        pagination: Optional pagination metadata for list responses.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str | None
    correlation_id: str | None
    api_version: str
    timestamp: object = Field(default_factory=utc_now)
    pagination: PaginationMeta | None = None

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, value: str) -> str:
        """Normalize and reject a blank API version.

        Args:
            value: API version from request context.

        Returns:
            Normalized API version.

        Raises:
            ValueError: If the API version is blank.
        """
        normalized = value.strip()

        if not normalized:
            raise ValueError("API version must not be blank")

        return normalized


class APIResponseModel[DataT](BaseModel):
    """Stable response contract for success and failure payloads.

    Type Parameters:
        DataT: Type of the successful response payload.
    """

    model_config = ConfigDict(extra="forbid")

    success: bool
    data: DataT | None
    error: ErrorBody | None
    meta: ResponseMeta


class APIResponse:
    """Construct JSON responses using the public response contract.

    This builder is intended for the API transport layer only. Domain and
    application services should return typed results or raise application
    exceptions rather than constructing HTTP responses directly.
    """

    @staticmethod
    def success(
        *,
        data: Any = None,
        status_code: int = status.HTTP_200_OK,
        pagination: PaginationMeta | None = None,
        headers: dict[str, str] | None = None,
    ) -> JSONResponse:
        """Create a successful JSON response.

        HTTP 204 is rejected because that status cannot contain a response
        body. Endpoints requiring 204 must return an empty FastAPI or Starlette
        ``Response``.

        Args:
            data: Successful response payload.
            status_code: HTTP success or redirect status code.
            pagination: Optional list pagination metadata.
            headers: Optional additional response headers.

        Returns:
            Serialized JSON response.

        Raises:
            ValueError: If ``status_code`` is invalid for a success response.
        """
        if status_code == status.HTTP_204_NO_CONTENT:
            raise ValueError("Use an empty Response for HTTP 204")

        if not 200 <= status_code < 400:
            raise ValueError("Success status_code must be between 200 and 399")

        body = APIResponseModel[Any](
            success=True,
            data=data,
            error=None,
            meta=APIResponse._meta(
                pagination=pagination,
            ),
        )

        response = JSONResponse(
            status_code=status_code,
            content=jsonable_encoder(
                body,
                exclude_none=False,
            ),
            headers=headers,
        )

        APIResponse._attach_context_headers(response)

        return response

    @staticmethod
    def error(
        *,
        error_code: str,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> JSONResponse:
        """Create a standardized client-safe error response.

        Args:
            error_code: Stable machine-readable error identifier.
            message: Human-readable client-safe explanation.
            status_code: HTTP client or server error status.
            details: Optional structured error details.
            headers: Optional additional response headers.

        Returns:
            Serialized JSON error response.

        Raises:
            ValueError: If ``status_code`` is outside the HTTP error range.
        """
        if not 400 <= status_code <= 599:
            raise ValueError("Error status_code must be between 400 and 599")

        body = APIResponseModel[Any](
            success=False,
            data=None,
            error=ErrorBody(
                code=error_code,
                message=message,
                details=details,
            ),
            meta=APIResponse._meta(),
        )

        response = JSONResponse(
            status_code=status_code,
            content=jsonable_encoder(
                body,
                exclude_none=False,
            ),
            headers=headers,
        )

        response.headers.setdefault(
            "Cache-Control",
            "no-store",
        )

        APIResponse._attach_context_headers(response)

        return response

    @staticmethod
    def _meta(
        *,
        pagination: PaginationMeta | None = None,
    ) -> ResponseMeta:
        """Build response metadata from the current request context.

        Args:
            pagination: Optional pagination metadata.

        Returns:
            Response metadata populated with request context identifiers.
        """
        return ResponseMeta(
            request_id=get_request_id(),
            correlation_id=get_correlation_id(),
            api_version=get_api_version(),
            pagination=pagination,
        )

    @staticmethod
    def _attach_context_headers(
        response: JSONResponse,
    ) -> None:
        """Attach request context identifiers to response headers.

        Args:
            response: Response receiving correlation headers.

        Side Effects:
            Mutates the response headers.
        """
        request_id = get_request_id()
        correlation_id = get_correlation_id()

        if request_id:
            response.headers["X-Request-ID"] = request_id

        if correlation_id:
            response.headers["X-Correlation-ID"] = correlation_id


__all__ = [
    "APIResponse",
    "APIResponseModel",
    "ErrorBody",
    "PaginationMeta",
    "ResponseMeta",
]
