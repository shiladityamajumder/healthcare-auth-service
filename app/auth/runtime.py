"""Process-wide authentication infrastructure container.

The runtime stores reusable authentication infrastructure that is safe to
share across requests, including cryptographic helpers, token management,
OTP handling, notification integration, and rate-limit enforcement.

Request-scoped business services remain owned by their vertical modules and
must not be stored in this container.

The rate limiter is created by the application lifespan and injected into this
runtime. This ensures Redis-backed rate limiting reuses the process-wide Redis
client instead of creating a separate connection pool.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from app.auth.notifications import AuthNotificationGateway
from app.auth.otp import OTPService
from app.auth.security import (
    PasswordManager,
    SecureHashing,
    TokenManager,
)
from app.core.config import AppSettings
from app.core.rate_limiting import RateLimiter


@dataclass(frozen=True, slots=True)
class AuthRuntime:
    """Immutable process-wide authentication infrastructure.

    Attributes:
        settings: Validated application configuration.
        passwords: Password hashing and verification manager.
        hashing: Shared keyed-hashing helper for sensitive identifiers.
        tokens: JWT and authentication-token manager.
        otp: OTP generation, hashing, and verification service.
        notifications: Authentication notification gateway.
        rate_limiter: Application-owned rate-limit backend.
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

        The application lifespan must create the rate limiter before calling
        this method. Redis-backed implementations therefore receive the shared
        Redis client owned by the lifecycle layer.

        Args:
            settings: Validated immutable application configuration.
            rate_limiter: Already-created rate-limit backend.

        Returns:
            Fully initialized authentication runtime.

        Raises:
            ValueError: If no rate limiter is provided.
        """
        if rate_limiter is None:
            raise ValueError(
                "AuthRuntime requires an initialized rate limiter."
            )

        hashing = SecureHashing(settings)

        return cls(
            settings=settings,
            passwords=PasswordManager(settings),
            hashing=hashing,
            tokens=TokenManager(settings),
            otp=OTPService(
                settings=settings,
                hashing=hashing,
            ),
            notifications=AuthNotificationGateway(settings),
            rate_limiter=rate_limiter,
        )


__all__ = ["AuthRuntime"]
