"""File: app/modules/admin_permissions/schemas.py
Permission and role-policy contracts."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_validator, model_validator

from app.common.auth_contracts import MessageResponse
from app.common.schemas import StrictModel


class CreatePermissionRequest(StrictModel):
    """Create one fine-grained permission master record."""

    code: str = Field(pattern=r"^[a-z][a-z0-9_.:-]{1,127}$")
    resource: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    action: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,63}$")
    description: str | None = Field(default=None, max_length=2000)


class UpdatePermissionRequest(StrictModel):
    """Partially update a permission master record."""

    code: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_.:-]{1,127}$",
    )
    resource: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_.-]{1,63}$",
    )
    action: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_-]{1,63}$",
    )
    description: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def require_update(self) -> UpdatePermissionRequest:
        """Reject empty updates and explicit nulls for database-required fields."""
        if not self.model_fields_set:
            raise ValueError("at least one permission field must be supplied")
        required_fields = {"code", "resource", "action"}
        explicit_nulls = [
            field
            for field in required_fields & self.model_fields_set
            if getattr(self, field) is None
        ]
        if explicit_nulls:
            raise ValueError(f"{', '.join(sorted(explicit_nulls))} cannot be null")
        return self


class PermissionResponse(StrictModel):
    """Public administrative permission representation."""

    id: uuid.UUID
    code: str
    resource: str
    action: str
    description: str | None
    created_at: datetime
    updated_at: datetime


class PermissionListResponse(StrictModel):
    """Materialized permission collection."""

    permissions: list[PermissionResponse]


class ReplaceRolePermissionsRequest(StrictModel):
    """Complete permission set for a role."""

    permission_ids: list[uuid.UUID] = Field(default_factory=list, max_length=1000)

    @field_validator("permission_ids")
    @classmethod
    def reject_duplicates(cls, value: list[uuid.UUID]) -> list[uuid.UUID]:
        """Reject duplicate permission identifiers in the request."""
        if len(value) != len(set(value)):
            raise ValueError("permission_ids must not contain duplicates")
        return value


class RolePermissionsResponse(StrictModel):
    """Role identifier and its complete active permission set."""

    role_id: uuid.UUID
    permissions: list[PermissionResponse]


__all__ = [
    "CreatePermissionRequest",
    "MessageResponse",
    "PermissionListResponse",
    "PermissionResponse",
    "ReplaceRolePermissionsRequest",
    "RolePermissionsResponse",
    "UpdatePermissionRequest",
]
