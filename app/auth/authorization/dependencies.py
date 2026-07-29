"""FastAPI authorization dependencies.

These dependencies consume an already authenticated ``UserPrincipal`` and
enforce role or permission requirements.

They do not decode tokens, query sessions, or load users.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends

from app.auth.request_context.dependencies import (
    get_current_user_principal,
)
from app.auth.request_context.principals import UserPrincipal
from app.common.exceptions import AuthorizationError

AuthorizationDependency = Callable[
    ...,
    Awaitable[UserPrincipal],
]


def require_permissions(
    *required: str,
) -> AuthorizationDependency:
    """Create a dependency requiring every supplied permission.

    Args:
        required: Permission codes required by the route.

    Returns:
        FastAPI dependency resolving the authorized principal.

    Raises:
        ValueError: If no nonblank permission codes are supplied.
    """
    normalized = _normalize_required_codes(
        required,
        requirement_name="permission",
    )

    async def dependency(
        principal: Annotated[
            UserPrincipal,
            Depends(get_current_user_principal),
        ],
    ) -> UserPrincipal:
        missing = normalized.difference(
            principal.permissions
        )

        if missing:
            raise AuthorizationError(
                "One or more required permissions are missing.",
                details={
                    "missing_permissions": sorted(missing),
                },
            )

        return principal

    return dependency


def require_roles(
    *required: str,
) -> AuthorizationDependency:
    """Create a dependency requiring every supplied role.

    Args:
        required: Role codes required by the route.

    Returns:
        FastAPI dependency resolving the authorized principal.

    Raises:
        ValueError: If no nonblank role codes are supplied.
    """
    normalized = _normalize_required_codes(
        required,
        requirement_name="role",
    )

    async def dependency(
        principal: Annotated[
            UserPrincipal,
            Depends(get_current_user_principal),
        ],
    ) -> UserPrincipal:
        missing = normalized.difference(
            principal.roles
        )

        if missing:
            raise AuthorizationError(
                "One or more required roles are missing.",
                details={
                    "missing_roles": sorted(missing),
                },
            )

        return principal

    return dependency


def _normalize_required_codes(
    values: tuple[str, ...],
    *,
    requirement_name: str,
) -> frozenset[str]:
    """Normalize required role or permission codes."""
    normalized = frozenset(
        value.strip()
        for value in values
        if value and value.strip()
    )

    if not normalized:
        raise ValueError(
            f"At least one {requirement_name} code is required."
        )

    return normalized


__all__ = [
    "AuthorizationDependency",
    "require_permissions",
    "require_roles",
]
