"""File: app/modules/admin_permissions/schemas.py
Permission and role-policy contracts."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_validator

from app.common.schemas import StrictModel


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
    "PermissionListResponse",
    "PermissionResponse",
    "ReplaceRolePermissionsRequest",
    "RolePermissionsResponse",
]
