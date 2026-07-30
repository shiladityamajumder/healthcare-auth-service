"""File: app/modules/password_management/openapi.py
OpenAPI metadata for password lifecycle endpoints."""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Auth Passwords"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
