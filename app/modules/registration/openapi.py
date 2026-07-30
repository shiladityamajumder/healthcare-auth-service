"""File: app/modules/registration/openapi.py

Purpose:
Exports the tag and authentication error metadata for registration routes.

Dependency flow:
Registration route declaration
-> TAG and RESPONSES
-> FastAPI router metadata
-> generated OpenAPI schema
"""

from typing import Any, cast

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Auth Registration"
RESPONSES = cast(dict[int | str, dict[str, Any]], AUTH_ERROR_RESPONSES)

__all__ = ["RESPONSES", "TAG"]
