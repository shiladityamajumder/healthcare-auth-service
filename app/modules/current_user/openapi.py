"""File: app/modules/current_user/openapi.py
OpenAPI metadata for current-user endpoints."""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Current User"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
