"""File: app/auth/request_context/principals.py

Purpose:
Defines the immutable authenticated identity and authorization state passed to
protected routes and authorization dependencies.

Dependency flow:
Verified access-token/session/account state
-> UserPrincipal
-> route-security or authorization dependency
-> protected route/service identifiers

A principal represents identity and authorization information validated from a
signed access token, persisted session, and current database authorization
state.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class UserPrincipal:
    """Authenticated user identity for one request.

    Attributes:
        user_id: Authenticated user identifier.
        session_id: Persisted authentication session identifier.
        roles: Effective global role codes.
        permissions: Effective global permission codes.
        auth_methods: Authentication methods reported by the access token.
    """

    user_id: uuid.UUID
    session_id: uuid.UUID

    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)
    auth_methods: tuple[str, ...] = ()


__all__ = [
    "UserPrincipal",
]
