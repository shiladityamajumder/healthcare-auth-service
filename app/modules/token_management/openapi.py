"""OpenAPI metadata for token and logout endpoints."""

from app.auth.openapi import AUTH_ERROR_RESPONSES

TAG = "Auth Tokens"
RESPONSES = AUTH_ERROR_RESPONSES

__all__ = ["RESPONSES", "TAG"]
