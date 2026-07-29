"""Role administration request and response contracts."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, model_validator

from app.common.auth_contracts import MessageResponse
from app.common.schemas import StrictModel


class CreateRoleRequest(StrictModel):
    """Create a non-system role."""

    code: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    name: str = Field(min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=2000)


class UpdateRoleRequest(StrictModel):
    """Partially update a role."""

    code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    name: str | None = Field(default=None, min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def require_update(self) -> "UpdateRoleRequest":
        """Require at least one mutable role field."""
        if not self.model_fields_set:
            raise ValueError("at least one role field must be supplied")
        return self


class RoleResponse(StrictModel):
    """Public administrative role representation."""

    id: uuid.UUID
    code: str
    name: str
    description: str | None
    is_system: bool
    created_at: datetime
    updated_at: datetime


class RoleListResponse(StrictModel):
    """Materialized role collection."""

    roles: list[RoleResponse]


__all__ = [
    "CreateRoleRequest",
    "MessageResponse",
    "RoleListResponse",
    "RoleResponse",
    "UpdateRoleRequest",
]
