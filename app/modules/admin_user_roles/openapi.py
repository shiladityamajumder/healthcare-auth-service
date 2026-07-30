"""File: app/modules/admin_user_roles/openapi.py

Purpose:
Exports the tag and authentication error metadata for user-role assignment
route declarations.

Dependency flow:
User-role route declaration
-> TAG and RESPONSES
-> FastAPI router metadata
-> generated OpenAPI schema
"""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Admin User Roles"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
