"""File: app/modules/email_verification/openapi.py
OpenAPI metadata for email verification endpoints."""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Auth Email Verification"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
