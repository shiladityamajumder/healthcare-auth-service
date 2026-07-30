"""File: app/modules/current_user/schemas.py
Current-user profile and authorization contracts owned by this module."""

from __future__ import annotations

from pydantic import Field

from app.common.auth_contracts import UserResponse
from app.common.schemas import StrictModel


class UpdateCurrentUserRequest(StrictModel):
    """Safe identity preferences editable by the authenticated user."""

    preferred_locale: str | None = Field(default=None, min_length=2, max_length=16)
    timezone: str | None = Field(default=None, min_length=3, max_length=64)


class UserRolesResponse(StrictModel):
    """Effective global role codes."""

    roles: list[str]


class UserPermissionsResponse(StrictModel):
    """Effective global permission codes."""

    permissions: list[str]


__all__ = [
    "UpdateCurrentUserRequest",
    "UserPermissionsResponse",
    "UserResponse",
    "UserRolesResponse",
]
