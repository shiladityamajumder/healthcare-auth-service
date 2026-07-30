"""File: app/modules/admin_users/schemas.py

Purpose:
Defines validated administrative user list, status-change, and logout request
and response contracts.

Dependency flow:
HTTP body/query or service result
-> strict Pydantic validation
-> admin user route/service
-> response-model serialization
"""

from __future__ import annotations

from pydantic import Field

from app.common.auth_contracts import MessageResponse, UserResponse
from app.common.schemas import StrictModel
from app.models.enums import UserStatus


class AdminUserListResponse(StrictModel):
    """Materialized page of users."""

    users: list[UserResponse]


class UpdateUserStatusRequest(StrictModel):
    """Administrative user status transition."""

    status: UserStatus
    reason: str = Field(min_length=3, max_length=255)
    revoke_sessions: bool = True


class AdminLogoutAllRequest(StrictModel):
    """Reason for administratively revoking every user session."""

    reason: str = Field(
        default="administrative_logout_all",
        min_length=3,
        max_length=255,
    )


__all__ = [
    "AdminLogoutAllRequest",
    "AdminUserListResponse",
    "MessageResponse",
    "UpdateUserStatusRequest",
    "UserResponse",
]
