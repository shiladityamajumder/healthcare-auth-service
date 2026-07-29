"""Process-wide authentication infrastructure container.

The runtime contains only reusable cryptographic, OTP, notification, and rate
limiting infrastructure. Request-scoped business services are created inside
their owning vertical modules.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.auth.notifications import AuthNotificationGateway
from app.auth.otp import OTPService
from app.auth.security import PasswordManager, SecureHashing, TokenManager
from app.core.config import AppSettings
from app.core.rate_limiting import RateLimiter, build_rate_limiter


@dataclass(frozen=True, slots=True)
class AuthRuntime:
    """Immutable process-wide authentication infrastructure."""

    settings: AppSettings
    passwords: PasswordManager
    hashing: SecureHashing
    tokens: TokenManager
    otp: OTPService
    notifications: AuthNotificationGateway
    rate_limiter: RateLimiter

    @classmethod
    def from_settings(cls, settings: AppSettings) -> "AuthRuntime":
        """Build the runtime once during FastAPI lifespan startup."""
        hashing = SecureHashing(settings)
        return cls(
            settings=settings,
            passwords=PasswordManager(settings),
            hashing=hashing,
            tokens=TokenManager(settings),
            otp=OTPService(settings=settings, hashing=hashing),
            notifications=AuthNotificationGateway(settings),
            rate_limiter=build_rate_limiter(settings),
        )


__all__ = ["AuthRuntime"]
