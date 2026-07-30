"""File: app/modules/admin_roles/openapi.py
OpenAPI metadata for role administration endpoints."""

from app.auth.infrastructure.openapi import AUTH_ERROR_RESPONSES

TAG = "Admin Roles"
RESPONSES = AUTH_ERROR_RESPONSES

__all__ = ["RESPONSES", "TAG"]
