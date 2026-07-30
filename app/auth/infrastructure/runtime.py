"""File: app/auth/infrastructure/runtime.py

Purpose:
Holds immutable process-wide authentication primitives created during FastAPI
startup and safely reused by request dependencies.

Dependency flow:
AppSettings and lifespan-owned limiter
-> build_auth_runtime()
-> AuthRuntime stored on app.state
-> AuthRuntimeDep
-> request-scoped workflow/service construction

The runtime stores reusable authentication infrastructure that is safe to
share across requests. Request-scoped business services, repositories,
database sessions, authenticated principals, and authorization claims must not
be stored in this container.

The application lifespan creates the rate limiter and injects it into this
runtime. Redis-backed rate limiting therefore reuses the process-wide Redis
client instead of creating an independent connection pool.

The lifespan owns resource shutdown. ``AuthRuntime`` holds references to
shared infrastructure but does not close those resources.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from app.auth.security.hashing import SecureHashing
from app.auth.security.passwords import PasswordManager
from app.auth.security.tokens import TokenManager
from app.auth.workflows.notifications import AuthNotificationGateway
from app.auth.workflows.otp import OTPService
from app.core.config import AppSettings
from app.core.rate_limiting import RateLimiter


@dataclass(frozen=True, slots=True)
class AuthRuntime:
    """Immutable process-wide authentication infrastructure.

    Attributes:
        settings: Validated immutable application configuration.
        passwords: Password hashing and verification manager.
        hashing: Keyed hashing helper for sensitive identifiers.
        tokens: Access, refresh, and recovery token manager.
        otp: OTP generation and verification service.
        notifications: Authentication notification integration.
        rate_limiter: Application-created rate-limit backend.
    """

    settings: AppSettings
    passwords: PasswordManager
    hashing: SecureHashing
    tokens: TokenManager
    otp: OTPService
    notifications: AuthNotificationGateway
    rate_limiter: RateLimiter

    @classmethod
    def from_settings(
        cls,
        settings: AppSettings,
        *,
        rate_limiter: RateLimiter,
    ) -> Self:
        """Build the process-wide authentication runtime.

        The rate limiter must already be initialized by the application
        lifespan. This method does not create Redis clients, database
        connections, repositories, or request-scoped services.

        Args:
            settings: Validated immutable application configuration.
            rate_limiter: Application-created rate-limit backend.

        Returns:
            Fully initialized authentication runtime.
        """
        hashing = SecureHashing(settings)
        passwords = PasswordManager(settings)
        tokens = TokenManager(settings)

        otp = OTPService(
            settings=settings,
            hashing=hashing,
        )

        notifications = AuthNotificationGateway(
            settings
        )

        return cls(
            settings=settings,
            passwords=passwords,
            hashing=hashing,
            tokens=tokens,
            otp=otp,
            notifications=notifications,
            rate_limiter=rate_limiter,
        )


__all__ = [
    "AuthRuntime",
]
