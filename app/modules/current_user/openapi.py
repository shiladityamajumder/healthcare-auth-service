"""OpenAPI metadata for current-user endpoints."""

from app.auth.openapi import AUTH_ERROR_RESPONSES

TAG = "Current User"
RESPONSES = AUTH_ERROR_RESPONSES

__all__ = ["RESPONSES", "TAG"]
