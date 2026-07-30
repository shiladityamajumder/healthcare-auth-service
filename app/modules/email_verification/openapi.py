"""File: app/modules/email_verification/openapi.py
OpenAPI metadata for email verification endpoints."""

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Auth Email Verification"
RESPONSES = AUTH_ERROR_RESPONSES

__all__ = ["RESPONSES", "TAG"]
