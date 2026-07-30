"""File: app/auth/request_context/principals.py

Purpose:
Defines the immutable authenticated identity and authorization state passed to
protected routes and authorization dependencies.

Dependency flow:
Verified access-token/session/account state
-> UserPrincipal
-> route-security or authorization dependency
-> protected route/service identifiers

A principal represents identity and authorization information that has already
been validated from a signed access token and, when configured, the persisted
session and current database authorization state.
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

    roles: frozenset[str] = field(
        default_factory=frozenset
    )
    permissions: frozenset[str] = field(
        default_factory=frozenset
    )
    auth_methods: tuple[str, ...] = ()

    def has_role(
        self,
        role_code: str,
    ) -> bool:
        """Return whether the principal has one role."""
        normalized = role_code.strip()

        return bool(
            normalized
            and normalized in self.roles
        )

    def has_permission(
        self,
        permission_code: str,
    ) -> bool:
        """Return whether the principal has one permission."""
        normalized = permission_code.strip()

        return bool(
            normalized
            and normalized in self.permissions
        )


__all__ = [
    "UserPrincipal",
]
