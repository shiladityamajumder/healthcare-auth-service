"""File: app/auth/infrastructure/openapi.py

Purpose:
Defines reusable authentication error-response metadata for accurate route
OpenAPI declarations.

Dependency flow:
Authentication module openapi.py
-> selected shared response definitions
-> APIRouter/route responses metadata
-> generated OpenAPI schema

This module contains transport documentation only. It does not handle
exceptions, create HTTP responses, or contain authentication business rules.

Route modules should use ``auth_error_responses`` to document only the errors
that a specific operation can actually return.

The response models declared here must remain aligned with the application's
global exception handlers. If an exception handler returns a different schema,
the OpenAPI documentation will be inaccurate.
"""

from __future__ import annotations

from typing import Any, Final

from app.common.response import APIResponseModel

type OpenAPIResponseSpec = dict[str, Any]


def _error_response(
    description: str,
) -> OpenAPIResponseSpec:
    """Create one authentication error response definition.

    Args:
        description: Human-readable OpenAPI response description.

    Returns:
        FastAPI-compatible response specification.
    """
    return {
        "model": APIResponseModel[None],
        "description": description,
    }


_AUTH_ERROR_RESPONSE_DEFINITIONS: Final[dict[int, OpenAPIResponseSpec]] = {
    400: _error_response("The request is malformed or contains unsupported input."),
    401: _error_response(
        "Authentication credentials, token, OTP, session, or recovery proof "
        "is missing, expired, or invalid."
    ),
    403: _error_response(
        "The authenticated principal does not have permission to perform the requested operation."
    ),
    404: _error_response("The requested authentication or identity resource was not found."),
    409: _error_response("The requested operation conflicts with the current persisted state."),
    422: _error_response("The request failed field validation or an authentication policy."),
    429: _error_response(
        "A rate limit, OTP cooldown, resend limit, or verification-attempt limit was exceeded."
    ),
    500: _error_response(
        "An unexpected internal error occurred. Implementation details are not exposed."
    ),
    503: _error_response("A required database or infrastructure dependency is unavailable."),
    504: _error_response(
        "A bounded database or infrastructure operation exceeded its configured deadline."
    ),
}


def auth_error_responses(
    *status_codes: int,
) -> dict[int, OpenAPIResponseSpec]:
    """Return OpenAPI error responses for selected status codes.

    Each response specification is copied before being returned so a route
    cannot mutate the shared definitions.

    When no status codes are supplied, all known authentication error
    definitions are returned. Route modules should normally provide an
    explicit status-code list.

    Args:
        status_codes: Error status codes applicable to one route.

    Returns:
        FastAPI-compatible response mapping.

    Raises:
        ValueError: If an unsupported status code is requested.
    """
    selected_codes = (
        tuple(dict.fromkeys(status_codes))
        if status_codes
        else tuple(_AUTH_ERROR_RESPONSE_DEFINITIONS)
    )

    unsupported_codes = [
        status_code
        for status_code in selected_codes
        if status_code not in _AUTH_ERROR_RESPONSE_DEFINITIONS
    ]

    if unsupported_codes:
        formatted_codes = ", ".join(str(status_code) for status_code in sorted(unsupported_codes))

        raise ValueError(f"Unsupported authentication OpenAPI response status: {formatted_codes}")

    return {
        status_code: dict(_AUTH_ERROR_RESPONSE_DEFINITIONS[status_code])
        for status_code in selected_codes
    }


# Backward-compatible complete response mapping. Existing route imports can
# continue using this constant during migration, but new routes should select
# their applicable responses through ``auth_error_responses``.
AUTH_ERROR_RESPONSES: Final[dict[int, OpenAPIResponseSpec]] = auth_error_responses()


__all__ = [
    "AUTH_ERROR_RESPONSES",
    "OpenAPIResponseSpec",
    "auth_error_responses",
]
