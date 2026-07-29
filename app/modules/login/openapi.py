"""OpenAPI metadata for login endpoints."""

from app.auth.openapi import AUTH_ERROR_RESPONSES

TAG = "Auth Login"
RESPONSES = AUTH_ERROR_RESPONSES

__all__ = ["RESPONSES", "TAG"]
