"""File: app/modules/current_user/schemas.py

Purpose:
Defines editable current-user preferences and effective role/permission
response contracts.

Dependency flow:
HTTP body or service result
-> strict Pydantic validation
-> current-user route/service
-> response-model serialization
"""

from __future__ import annotations

import uuid

from pydantic import Field

from app.common.auth_contracts import (
    AuthenticatedUserResponse,
    CurrentAuthorizationResponse,
)
from app.common.schemas import StrictModel


class UpdateCurrentUserRequest(StrictModel):
    """Identity preferences and profile values editable by their owner."""

    preferred_locale: str | None = Field(default=None, min_length=2, max_length=16)
    timezone: str | None = Field(default=None, min_length=3, max_length=64)
    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    preferred_name: str | None = Field(default=None, min_length=1, max_length=100)
    avatar_file_id: uuid.UUID | None = None


__all__ = [
    "AuthenticatedUserResponse",
    "CurrentAuthorizationResponse",
    "UpdateCurrentUserRequest",
]
