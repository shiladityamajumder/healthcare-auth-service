"""Shared access/refresh token and session creation infrastructure."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.auth.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.auth.security.tokens import TokenManager
from app.models.identity import Sessions
from app.utils.datetime_utils import utc_now


class DeviceMetadataPort(Protocol):
    """Device fields accepted from session-creating request schemas."""

    device_id: str | None
    device_type: str | None


class SessionWriterPort(Protocol):
    """Persistence operation required by the token issuer."""

    def add_session(self, session_record: Sessions) -> None:
        """Stage a newly issued session for persistence."""
        ...


@dataclass(frozen=True, slots=True)
class IssuedSessionTokens:
    """Raw token pair and expiry metadata returned to owning modules."""

    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


@dataclass(slots=True)
class SessionTokenIssuer:
    """Create a refresh-token family and its first device session."""

    tokens: TokenManager
    hashing: SecureHashing

    def issue(
        self,
        *,
        user_id: uuid.UUID,
        roles: list[str],
        permissions: list[str],
        session_writer: SessionWriterPort,
        request_context: AuthRequestContext,
        device: DeviceMetadataPort,
        auth_methods: list[str],
    ) -> IssuedSessionTokens:
        """Issue a new credential and its associated persisted state."""
        now = utc_now()
        session_id = uuid.uuid4()
        family_id = uuid.uuid4()
        refresh = self.tokens.create_refresh_token(
            user_id=user_id,
            session_id=session_id,
            family_id=family_id,
        )
        access = self.tokens.create_access_token(
            user_id=user_id,
            session_id=session_id,
            roles=roles,
            permissions=permissions,
            auth_methods=auth_methods,
        )
        session_writer.add_session(
            Sessions(
                id=session_id,
                user_id=user_id,
                refresh_token_hash=self.hashing.token_hash(refresh.token),
                token_family_id=family_id,
                device_id=device.device_id or request_context.device_id,
                device_type=device.device_type or request_context.platform,
                ip_address=request_context.ip_address,
                user_agent=request_context.user_agent,
                expires_at=refresh.expires_at,
                last_seen_at=now,
            )
        )
        return IssuedSessionTokens(
            access_token=access.token,
            refresh_token=refresh.token,
            access_expires_at=access.expires_at,
            refresh_expires_at=refresh.expires_at,
        )


__all__ = [
    "DeviceMetadataPort",
    "IssuedSessionTokens",
    "SessionTokenIssuer",
    "SessionWriterPort",
]
