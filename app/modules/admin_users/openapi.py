"""OpenAPI metadata for administrative user endpoints."""

from app.auth.openapi import AUTH_ERROR_RESPONSES

TAG = "Admin Users"
RESPONSES = AUTH_ERROR_RESPONSES

__all__ = ["RESPONSES", "TAG"]
