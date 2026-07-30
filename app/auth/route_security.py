"""File: app/auth/route_security.py

Purpose:
Builds composable FastAPI dependencies from declarative authentication,
authorization, and generic rate-limit policies.

Dependency flow:
Module Annotated access alias
-> secure_route(RouteSecurityPolicy)
-> required or optional principal resolution
-> permission/role validation
-> APIRateLimits enforcement
-> UserPrincipal returned to the route
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request

from app.auth.api_rate_limits import APIRateLimits
from app.auth.request_context.dependencies import (
    AuthRuntimeDep,
    CurrentUserDep,
    OptionalUserDep,
    PrincipalRequestContextDep,
    RateLimitRequestContextDep,
)
from app.auth.request_context.principals import UserPrincipal
from app.auth.security_policy import RouteSecurityPolicy
from app.common.exceptions import AuthorizationError

SecurityDependency = Callable[..., Awaitable[UserPrincipal | None]]
_POLICY_ATTRIBUTE = "__route_security_policy__"


def get_api_rate_limits(runtime: AuthRuntimeDep) -> APIRateLimits:
    """Build a request facade over the process-wide limiter and hashing key."""
    return APIRateLimits(
        settings=runtime.settings,
        limiter=runtime.rate_limiter,
        hashing=runtime.hashing,
    )


# FastAPI builds this request-safe facade over process-wide limiter resources.
APIRateLimitsDep = Annotated[
    APIRateLimits,
    Depends(get_api_rate_limits),
]


def secure_route(policy: RouteSecurityPolicy) -> SecurityDependency:
    """Create a FastAPI dependency enforcing one complete route policy.

    Required policies resolve the normal bearer principal. Optional policies
    accept an absent bearer token but still reject an invalid supplied token.
    A marker is attached for contract tests that audit protected routes.
    """

    # Protected routes use the authoritative bearer/session dependency.
    if policy.authentication_required:

        async def protected_dependency(
            request: Request,
            principal: CurrentUserDep,
            context: PrincipalRequestContextDep,
            rate_limits: APIRateLimitsDep,
        ) -> UserPrincipal:
            """Resolve and enforce a required-principal route policy."""
            # Authentication resolves first; authorization evaluates the fresh
            # principal, and rate limiting runs before route business logic.
            _authorize(policy=policy, principal=principal)
            await rate_limits.enforce(
                policy=policy.rate_limit,
                operation=_operation_name(request),
                context=context,
                principal=principal,
            )
            return principal

        # Metadata lets contract tests detect accidentally unprotected routes.
        setattr(protected_dependency, _POLICY_ATTRIBUTE, policy)
        return protected_dependency

    # Public routes may enrich a request with a principal when a token exists.
    async def optional_dependency(
        request: Request,
        principal: OptionalUserDep,
        context: RateLimitRequestContextDep,
        rate_limits: APIRateLimitsDep,
    ) -> UserPrincipal | None:
        """Enforce a public policy with optional authenticated enrichment."""
        # Absence remains anonymous, while an invalid supplied token already
        # failed inside OptionalUserDep and cannot downgrade to public access.
        if principal is not None:
            _authorize(policy=policy, principal=principal)
        await rate_limits.enforce(
            policy=policy.rate_limit,
            operation=_operation_name(request),
            context=context,
            principal=principal,
        )
        return principal

    setattr(optional_dependency, _POLICY_ATTRIBUTE, policy)
    return optional_dependency


def route_security_policy(dependency: object) -> RouteSecurityPolicy | None:
    """Return policy metadata attached to a generated dependency."""
    value = getattr(dependency, _POLICY_ATTRIBUTE, None)
    return value if isinstance(value, RouteSecurityPolicy) else None


def _authorize(*, policy: RouteSecurityPolicy, principal: UserPrincipal) -> None:
    """Enforce every permission and role declared by a policy."""
    missing_permissions = policy.permissions.difference(principal.permissions)
    if missing_permissions:
        raise AuthorizationError(
            "One or more required permissions are missing.",
            details={"missing_permissions": sorted(missing_permissions)},
        )

    missing_roles = policy.roles.difference(principal.roles)
    if missing_roles:
        raise AuthorizationError(
            "One or more required roles are missing.",
            details={"missing_roles": sorted(missing_roles)},
        )


def _operation_name(request: Request) -> str:
    """Return a stable, non-user-controlled operation name for limiter keys."""
    route = request.scope.get("route")
    name = getattr(route, "name", None)
    if isinstance(name, str) and name.strip():
        return name
    return f"{request.method.casefold()}:{request.url.path}"


__all__ = [
    "APIRateLimitsDep",
    "SecurityDependency",
    "get_api_rate_limits",
    "route_security_policy",
    "secure_route",
]
