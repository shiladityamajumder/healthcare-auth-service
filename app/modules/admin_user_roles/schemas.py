"""File: app/modules/admin_user_roles/schemas.py
User-role assignment request and response contracts."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, model_validator

from app.common.auth_contracts import MessageResponse
from app.common.schemas import StrictModel


class AssignUserRoleRequest(StrictModel):
    """Create a scoped or global role assignment."""

    role_id: uuid.UUID
    scope_type: str | None = Field(default=None, min_length=2, max_length=32)
    scope_id: uuid.UUID | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    is_active: bool = True

    @model_validator(mode="after")
    def validate_scope_and_window(self) -> AssignUserRoleRequest:
        """Validate role scope completeness and validity dates."""
        if (self.scope_type is None) != (self.scope_id is None):
            raise ValueError("scope_type and scope_id must be supplied together")
        if (
            self.valid_from is not None
            and self.valid_until is not None
            and self.valid_until <= self.valid_from
        ):
            raise ValueError("valid_until must be later than valid_from")
        return self


class UpdateUserRoleRequest(StrictModel):
    """Update assignment scope, validity, or active state."""

    scope_type: str | None = Field(default=None, min_length=2, max_length=32)
    scope_id: uuid.UUID | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def validate_update(self) -> UpdateUserRoleRequest:
        """Validate assignment update fields, scope, and validity dates."""
        if not self.model_fields_set:
            raise ValueError("at least one assignment field must be supplied")
        scope_fields = {"scope_type", "scope_id"} & self.model_fields_set
        if scope_fields and (self.scope_type is None) != (self.scope_id is None):
            raise ValueError("scope_type and scope_id must be supplied together")
        if (
            self.valid_from is not None
            and self.valid_until is not None
            and self.valid_until <= self.valid_from
        ):
            raise ValueError("valid_until must be later than valid_from")
        return self


class UserRoleResponse(StrictModel):
    """Public administrative role assignment representation."""

    id: uuid.UUID
    user_id: uuid.UUID
    role_id: uuid.UUID
    role_code: str
    role_name: str
    scope_type: str | None
    scope_id: uuid.UUID | None
    valid_from: datetime | None
    valid_until: datetime | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class UserRoleListResponse(StrictModel):
    """Materialized assignment collection for one user."""

    assignments: list[UserRoleResponse]


__all__ = [
    "AssignUserRoleRequest",
    "MessageResponse",
    "UpdateUserRoleRequest",
    "UserRoleListResponse",
    "UserRoleResponse",
]
