"""File: app/modules/session_management/openapi.py

Purpose:
Exports the tag and authentication error metadata for session-management
routes.

Dependency flow:
Session route declaration
-> TAG and RESPONSES
-> FastAPI router metadata
-> generated OpenAPI schema
"""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Auth Sessions"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
