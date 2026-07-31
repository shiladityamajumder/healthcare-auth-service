"""File: app/auth/workflows/session_tokens.py

Purpose:
Creates a persisted session record and matching access/refresh token pair for
registration, login, verification, and password workflows.

Dependency flow:
Owning service transaction and authorization claims
-> SessionTokenIssuer
-> refresh-token hashing and session writer
-> TokenManager access/refresh signing
-> token pair returned to owning service

This module coordinates token issuance and stages the corresponding persisted
session record through an injected writer.

The owning registration or login service remains responsible for the database
transaction and commit.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.auth.request_context.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.auth.security.tokens import TokenManager
from app.models.identity import Sessions
from app.utils.datetime_utils import utc_now


class SessionWriterPort(Protocol):
    """Persistence operation required by the session token issuer."""

    def add_session(
        self,
        session_record: Sessions,
    ) -> None:
        """Stage a newly issued session in the current transaction."""

        ...


@dataclass(frozen=True, slots=True)
class IssuedSessionTokens:
    """Raw token pair and expiration metadata returned to owning modules."""

    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


@dataclass(frozen=True, slots=True)
class SessionTokenIssuer:
    """Create an initial refresh-token family and persisted device session.

    Device identity and type are established only at session creation. Refresh
    workflows may validate a supplied device identifier but must not replace
    these stored values.
    """

    tokens: TokenManager
    hashing: SecureHashing

    def issue(
        self,
        *,
        user_id: uuid.UUID,
        roles: Sequence[str],
        permissions: Sequence[str],
        session_writer: SessionWriterPort,
        request_context: AuthRequestContext,
        auth_methods: Sequence[str],
    ) -> IssuedSessionTokens:
        """Issue a token pair and stage its persisted session.

        This method does not commit the transaction. The owning authentication
        workflow must commit only after all login or registration state has
        been staged successfully.

        Args:
            user_id: Authenticated user identifier.
            roles: Effective global role codes.
            permissions: Effective global permission codes.
            session_writer: Session persistence implementation.
            request_context: Validated request and header metadata.
            auth_methods: Authentication method references.

        Returns:
            Raw access and refresh tokens with their expiration timestamps.
        """
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

        # Device metadata has one transport source: validated headers captured
        # in the immutable request context. Once persisted, device identity and
        # type remain immutable for the lifetime of this session.
        device_type = _first_nonblank(
            request_context.device_type,
            request_context.platform,
        )

        session_record = Sessions(
            id=session_id,
            user_id=user_id,
            refresh_token_hash=self.hashing.token_hash(
                refresh.token
            ),
            token_family_id=family_id,
            device_id=request_context.device_id,
            device_type=device_type,
            ip_address=request_context.ip_address,
            user_agent=request_context.user_agent,
            expires_at=refresh.expires_at,
            last_seen_at=now,
        )

        session_writer.add_session(
            session_record
        )

        return IssuedSessionTokens(
            access_token=access.token,
            refresh_token=refresh.token,
            access_expires_at=access.expires_at,
            refresh_expires_at=refresh.expires_at,
        )


def _first_nonblank(
    *values: str | None,
) -> str | None:
    """Return the first nonblank metadata value."""
    for value in values:
        if value is None:
            continue

        normalized = value.strip()

        if normalized:
            return normalized

    return None


__all__ = [
    "IssuedSessionTokens",
    "SessionTokenIssuer",
    "SessionWriterPort",
]
