"""File: app/modules/token_management/openapi.py
OpenAPI metadata for token and logout endpoints."""

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Auth Tokens"
RESPONSES = AUTH_ERROR_RESPONSES

__all__ = ["RESPONSES", "TAG"]
