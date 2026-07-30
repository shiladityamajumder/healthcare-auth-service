"""File: app/auth/security_policy.py

Purpose:
Defines immutable declarative metadata for route authentication,
authorization claims, and generic API rate-limit selection.

Dependency flow:
Module dependency alias
-> RouteSecurityPolicy construction and normalization
-> secure_route()
-> per-request security dependency

Policies describe authentication, authorization, and generic API rate limits
without wrapping route functions or hiding their signatures from FastAPI.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RateLimitPolicy(StrEnum):
    """Risk-based generic API rate-limit profiles."""

    NONE = "none"
    STANDARD = "standard"
    SENSITIVE = "sensitive"
    ADMIN_READ = "admin_read"
    ADMIN_WRITE = "admin_write"


@dataclass(frozen=True, slots=True)
class RouteSecurityPolicy:
    """Security requirements composed into one route dependency.

    ``authentication_required=False`` is supported for public endpoints with
    optional bearer enrichment. Public policies cannot require roles or
    permissions because authorization without authentication is invalid.
    """

    authentication_required: bool = True
    permissions: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    rate_limit: RateLimitPolicy = RateLimitPolicy.STANDARD

    def __post_init__(self) -> None:
        """Normalize codes and reject internally inconsistent policies."""
        # Normalize once so every downstream authorization check sees clean codes.
        normalized_permissions = _normalize_codes(self.permissions, field_name="permissions")
        normalized_roles = _normalize_codes(self.roles, field_name="roles")
        object.__setattr__(self, "permissions", normalized_permissions)
        object.__setattr__(self, "roles", normalized_roles)

        # Authorization claims have no meaning when authentication is optional.
        if not self.authentication_required and (normalized_permissions or normalized_roles):
            raise ValueError("Public route policies cannot require permissions or roles.")


def _normalize_codes(values: frozenset[str], *, field_name: str) -> frozenset[str]:
    """Normalize policy codes and reject blank entries."""
    normalized = frozenset(value.strip() for value in values if value and value.strip())
    if len(normalized) != len(values):
        raise ValueError(f"Route security {field_name} must contain only nonblank codes.")
    return normalized


__all__ = ["RateLimitPolicy", "RouteSecurityPolicy"]
