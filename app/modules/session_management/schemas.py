"""User-session response contracts owned by this module."""

from __future__ import annotations

import uuid
from datetime import datetime

from app.common.auth_contracts import MessageResponse
from app.common.schemas import StrictModel


class SessionResponse(StrictModel):
    """Non-sensitive active session metadata."""

    id: uuid.UUID
    device_id: str | None
    device_type: str | None
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    current: bool = False


class SessionListResponse(StrictModel):
    """Active sessions for the authenticated user."""

    sessions: list[SessionResponse]


__all__ = ["MessageResponse", "SessionListResponse", "SessionResponse"]
