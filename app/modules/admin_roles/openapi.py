"""File: app/modules/admin_roles/openapi.py
OpenAPI metadata for role administration endpoints."""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Admin Roles"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
