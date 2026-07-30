"""File: app/modules/admin_users/openapi.py
OpenAPI metadata for administrative user endpoints."""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Admin Users"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
