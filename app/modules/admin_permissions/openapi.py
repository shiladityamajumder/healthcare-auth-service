"""OpenAPI metadata for permission and role-policy endpoints."""

from app.auth.openapi import AUTH_ERROR_RESPONSES

TAG = "Admin Permissions"
RESPONSES = AUTH_ERROR_RESPONSES

__all__ = ["RESPONSES", "TAG"]
