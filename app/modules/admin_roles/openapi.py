"""File: app/modules/admin_roles/openapi.py

Purpose:
Exports the tag and authentication error metadata used by administrative role
route declarations.

Dependency flow:
Role route declaration
-> TAG and RESPONSES
-> FastAPI router metadata
-> generated OpenAPI schema
"""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Admin Roles"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
