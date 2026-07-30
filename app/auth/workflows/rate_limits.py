"""File: app/auth/workflows/rate_limits.py
Authentication-specific rate-limit policy and key construction.

This module converts authentication operations and request metadata into
bounded, privacy-preserving rate-limit keys.

The generic rate-limit backend and enforcement mechanism remain in
``app.core.rate_limiting``.
"""

from __future__ import annotations

from app.auth.request_context.context import AuthRequestContext
from app.auth.security.hashing import SecureHashing
from app.core.config import AppSettings
from app.core.rate_limiting import (
    RateLimiter,
    enforce_rate_limit,
)


class AuthRateLimits:
    """Construct and enforce authentication-specific rate-limit keys."""

    def __init__(
        self,
        *,
        settings: AppSettings,
        limiter: RateLimiter,
        hashing: SecureHashing,
    ) -> None:
        """Initialize authentication rate-limit policy.

        Args:
            settings: Validated authentication rate-limit settings.
            limiter: Process-wide rate-limit backend.
            hashing: Shared secure hashing infrastructure.
        """
        self._settings = settings
        self._limiter = limiter
        self._hashing = hashing

    async def registration(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
    ) -> None:
        """Enforce registration rate limits."""
        await self._enforce(
            operation="registration",
            context=context,
            identity=identity,
            limit=self._settings.REGISTRATION_RATE_LIMIT,
            window_seconds=(
                self._settings
                .REGISTRATION_RATE_WINDOW_SECONDS
            ),
        )

    async def login(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
    ) -> None:
        """Enforce password or OTP login request limits."""
        await self._enforce(
            operation="login",
            context=context,
            identity=identity,
            limit=self._settings.LOGIN_RATE_LIMIT,
            window_seconds=(
                self._settings
                .LOGIN_RATE_WINDOW_SECONDS
            ),
        )

    async def otp_request(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
        purpose: str,
    ) -> None:
        """Enforce OTP issuance limits for one purpose."""
        normalized_purpose = self._operation_component(
            purpose,
            field_name="purpose",
        )

        await self._enforce(
            operation=f"otp-request:{normalized_purpose}",
            context=context,
            identity=identity,
            limit=self._settings.OTP_REQUEST_RATE_LIMIT,
            window_seconds=(
                self._settings
                .OTP_REQUEST_RATE_WINDOW_SECONDS
            ),
        )

    async def otp_verify(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
        purpose: str,
    ) -> None:
        """Enforce OTP verification limits for one purpose."""
        normalized_purpose = self._operation_component(
            purpose,
            field_name="purpose",
        )

        await self._enforce(
            operation=f"otp-verify:{normalized_purpose}",
            context=context,
            identity=identity,
            limit=self._settings.OTP_VERIFY_RATE_LIMIT,
            window_seconds=(
                self._settings
                .OTP_VERIFY_RATE_WINDOW_SECONDS
            ),
        )

    async def password_reset(
        self,
        *,
        context: AuthRequestContext,
        identity: str,
    ) -> None:
        """Enforce password-recovery and reset request limits."""
        await self._enforce(
            operation="password-reset",
            context=context,
            identity=identity,
            limit=self._settings.PASSWORD_RESET_RATE_LIMIT,
            window_seconds=(
                self._settings
                .PASSWORD_RESET_RATE_WINDOW_SECONDS
            ),
        )

    async def refresh(
        self,
        *,
        context: AuthRequestContext,
        token_fingerprint: str,
    ) -> None:
        """Enforce refresh-token rotation request limits."""
        await self._enforce(
            operation="token-refresh",
            context=context,
            identity=token_fingerprint,
            limit=self._settings.TOKEN_REFRESH_RATE_LIMIT,
            window_seconds=(
                self._settings
                .TOKEN_REFRESH_RATE_WINDOW_SECONDS
            ),
        )

    async def logout(
        self,
        *,
        context: AuthRequestContext,
        token_fingerprint: str,
    ) -> None:
        """Enforce refresh-token logout limits by token fingerprint and origin."""
        # The shared helper hashes the fingerprint before building limiter keys.
        await self._enforce(
            operation="token-logout",
            context=context,
            identity=token_fingerprint,
            limit=self._settings.TOKEN_LOGOUT_RATE_LIMIT,
            window_seconds=self._settings.TOKEN_LOGOUT_RATE_WINDOW_SECONDS,
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
        """Build multidimensional keys and enforce one rate policy."""
        normalized_operation = self._operation_name(
            operation
        )
        normalized_identity = self._key_value(
            identity,
            field_name="identity",
        )

        keys = [
            self._key(
                operation=normalized_operation,
                dimension="identity",
                value=normalized_identity,
            ),
        ]

        if context.ip_address is not None:
            keys.append(
                self._key(
                    operation=normalized_operation,
                    dimension="ip",
                    value=self._key_value(
                        context.ip_address,
                        field_name="ip_address",
                    ),
                )
            )

        if context.device_id is not None:
            keys.append(
                self._key(
                    operation=normalized_operation,
                    dimension="device",
                    value=self._key_value(
                        context.device_id,
                        field_name="device_id",
                    ),
                )
            )

        if context.client_id is not None:
            keys.append(
                self._key(
                    operation=normalized_operation,
                    dimension="client",
                    value=self._key_value(
                        context.client_id,
                        field_name="client_id",
                    ),
                )
            )

        await enforce_rate_limit(
            self._limiter,
            keys=list(
                dict.fromkeys(keys)
            ),
            limit=limit,
            window_seconds=window_seconds,
        )

    def _key(
        self,
        *,
        operation: str,
        dimension: str,
        value: str,
    ) -> str:
        """Create one privacy-preserving rate-limit key."""
        digest = self._hashing.digest(
            value,
            namespace=f"rate-limit:{dimension}",
        )

        return (
            f"auth:{operation}:"
            f"{dimension}:{digest}"
        )

    @staticmethod
    def _operation_name(
        value: str,
    ) -> str:
        """Validate a complete internal rate-limit operation name."""
        normalized = value.strip().casefold()

        if not normalized:
            raise ValueError(
                "Rate-limit operation must not be blank."
            )

        if any(
            ord(character) < 32 or ord(character) == 127
            for character in normalized
        ):
            raise ValueError(
                "Rate-limit operation contains invalid control characters."
            )

        return normalized

    @staticmethod
    def _operation_component(
        value: str,
        *,
        field_name: str,
    ) -> str:
        """Normalize a dynamic rate-limit operation component."""
        normalized = value.strip().casefold()

        if not normalized:
            raise ValueError(
                f"{field_name} must not be blank."
            )

        if ":" in normalized:
            raise ValueError(
                f"{field_name} must not contain a colon."
            )

        if any(
            ord(character) < 32 or ord(character) == 127
            for character in normalized
        ):
            raise ValueError(
                f"{field_name} contains invalid control characters."
            )

        return normalized

    @staticmethod
    def _key_value(
        value: str,
        *,
        field_name: str,
    ) -> str:
        """Validate a rate-limit key dimension without changing its case."""
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                f"{field_name} must not be blank."
            )

        if any(
            ord(character) < 32 or ord(character) == 127
            for character in normalized
        ):
            raise ValueError(
                f"{field_name} contains invalid control characters."
            )

        return normalized


__all__ = [
    "AuthRateLimits",
]
