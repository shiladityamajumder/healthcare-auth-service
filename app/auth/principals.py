"""Shared authenticated user principal infrastructure."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class UserPrincipal:
    """Authenticated user identity resolved from a signed access token."""

    user_id: uuid.UUID
    session_id: uuid.UUID
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)
    auth_methods: tuple[str, ...] = ()


__all__ = ["UserPrincipal"]
