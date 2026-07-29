"""Shared authentication rate limits infrastructure."""

from __future__ import annotations

from app.core.config import AppSettings
from app.core.rate_limiting import RateLimiter, enforce_rate_limit
from app.auth.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing


class AuthRateLimits:
    """Authentication-specific rate-limit key construction and policy."""

    def __init__(
        self,
        *,
        settings: AppSettings,
        limiter: RateLimiter,
        hashing: SecureHashing,
    ) -> None:
        self._settings = settings
        self._limiter = limiter
        self._hashing = hashing

    async def registration(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
    ) -> None:
        """Enforce registration rate limits for identity and request context."""
        await self._enforce(
            operation="registration",
            context=context,
            identity=identity,
            limit=self._settings.REGISTRATION_RATE_LIMIT,
            window_seconds=self._settings.REGISTRATION_RATE_WINDOW_SECONDS,
        )

    async def login(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
    ) -> None:
        """Authenticate credentials and create a persisted user session."""
        await self._enforce(
            operation="login",
            context=context,
            identity=identity,
            limit=self._settings.LOGIN_RATE_LIMIT,
            window_seconds=self._settings.LOGIN_RATE_WINDOW_SECONDS,
        )

    async def otp_request(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
        purpose: str,
    ) -> None:
        """Enforce OTP-request rate limits for the selected purpose."""
        await self._enforce(
            operation=f"otp-request:{purpose}",
            context=context,
            identity=identity,
            limit=self._settings.OTP_REQUEST_RATE_LIMIT,
            window_seconds=self._settings.OTP_REQUEST_RATE_WINDOW_SECONDS,
        )

    async def otp_verify(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
        purpose: str,
    ) -> None:
        """Enforce OTP-verification rate limits for the selected purpose."""
        await self._enforce(
            operation=f"otp-verify:{purpose}",
            context=context,
            identity=identity,
            limit=self._settings.OTP_VERIFY_RATE_LIMIT,
            window_seconds=self._settings.OTP_VERIFY_RATE_WINDOW_SECONDS,
        )

    async def password_reset(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
    ) -> None:
        """Enforce password-reset rate limits for identity and request context."""
        await self._enforce(
            operation="password-reset",
            context=context,
            identity=identity,
            limit=self._settings.PASSWORD_RESET_RATE_LIMIT,
            window_seconds=self._settings.PASSWORD_RESET_RATE_WINDOW_SECONDS,
        )

    async def refresh(
        self,
        *,
        context: AuthRequestContext,
        token_fingerprint: str,
    ) -> None:
        """Rotate the refresh token and return a new token pair."""
        await self._enforce(
            operation="token-refresh",
            context=context,
            identity=token_fingerprint,
            limit=self._settings.TOKEN_REFRESH_RATE_LIMIT,
            window_seconds=self._settings.TOKEN_REFRESH_RATE_WINDOW_SECONDS,
        )

    async def _enforce(
        self,
        *,
        operation: str,
        context: AuthRequestContext,
        identity: str,
        limit: int,
        window_seconds: int,
    ) -> None:
        keys = [
            self._key(operation, "identity", identity),
        ]
        if context.ip_address:
            keys.append(self._key(operation, "ip", context.ip_address))
        if context.device_id:
            keys.append(self._key(operation, "device", context.device_id))
        if context.client_id:
            keys.append(self._key(operation, "client", context.client_id))
        await enforce_rate_limit(
            self._limiter,
            keys=keys,
            limit=limit,
            window_seconds=window_seconds,
        )

    def _key(self, operation: str, dimension: str, value: str) -> str:
        digest = self._hashing.digest(
            value.strip().casefold(),
            namespace=f"rate-limit:{dimension}",
        )
        return f"auth:{operation}:{dimension}:{digest}"


__all__ = ["AuthRateLimits"]
