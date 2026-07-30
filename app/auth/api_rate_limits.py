"""File: app/auth/api_rate_limits.py

Purpose:
Applies risk-based generic API limits using privacy-preserving request and
principal dimensions.

Dependency flow:
secure_route() dependency
-> APIRateLimits.enforce()
-> configured RateLimitPolicy values
-> domain-separated hashed keys
-> shared core RateLimiter
-> success or RateLimitError
"""

from __future__ import annotations

from app.auth.request_context.context import AuthRequestContext
from app.auth.request_context.principals import UserPrincipal
from app.auth.security.hashing import SecureHashing
from app.auth.security_policy import RateLimitPolicy
from app.core.config import AppSettings
from app.core.rate_limiting import RateLimiter, enforce_rate_limit


class APIRateLimits:
    """Enforce generic API policies using privacy-preserving dimensions."""

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

    async def enforce(
        self,
        *,
        policy: RateLimitPolicy,
        operation: str,
        context: AuthRequestContext,
        principal: UserPrincipal | None = None,
    ) -> None:
        """Consume the configured limit for all available trusted dimensions."""
        if policy is RateLimitPolicy.NONE:
            return

        normalized_operation = _normalize_operation(operation)
        limit, window_seconds = self._resolve_policy(policy)
        keys: list[str] = []

        # Charge every available dimension so one user cannot bypass a limit by
        # changing only a device, client identifier, or network address.
        if principal is not None:
            keys.append(
                self._key(
                    operation=normalized_operation,
                    dimension="user",
                    value=str(principal.user_id),
                )
            )
        if context.ip_address is not None:
            keys.append(
                self._key(
                    operation=normalized_operation,
                    dimension="ip",
                    value=context.ip_address,
                )
            )
        if context.client_id is not None:
            keys.append(
                self._key(
                    operation=normalized_operation,
                    dimension="client",
                    value=context.client_id,
                )
            )
        if context.device_id is not None:
            keys.append(
                self._key(
                    operation=normalized_operation,
                    dimension="device",
                    value=context.device_id,
                )
            )

        # Public endpoints still receive a deterministic fallback bucket.
        if not keys:
            keys.append(
                self._key(
                    operation=normalized_operation,
                    dimension="anonymous",
                    value="unknown",
                )
            )

        await enforce_rate_limit(
            self._limiter,
            keys=list(dict.fromkeys(keys)),
            limit=limit,
            window_seconds=window_seconds,
        )

    def _resolve_policy(self, policy: RateLimitPolicy) -> tuple[int, int]:
        """Resolve a named policy to validated configuration values."""
        policies = {
            RateLimitPolicy.STANDARD: (
                self._settings.API_STANDARD_RATE_LIMIT,
                self._settings.API_STANDARD_RATE_WINDOW_SECONDS,
            ),
            RateLimitPolicy.SENSITIVE: (
                self._settings.API_SENSITIVE_RATE_LIMIT,
                self._settings.API_SENSITIVE_RATE_WINDOW_SECONDS,
            ),
            RateLimitPolicy.ADMIN_READ: (
                self._settings.API_ADMIN_READ_RATE_LIMIT,
                self._settings.API_ADMIN_READ_RATE_WINDOW_SECONDS,
            ),
            RateLimitPolicy.ADMIN_WRITE: (
                self._settings.API_ADMIN_WRITE_RATE_LIMIT,
                self._settings.API_ADMIN_WRITE_RATE_WINDOW_SECONDS,
            ),
        }
        try:
            return policies[policy]
        except KeyError as exc:
            raise ValueError(f"Unsupported API rate-limit policy: {policy}") from exc

    def _key(self, *, operation: str, dimension: str, value: str) -> str:
        """Build a domain-separated key without exposing raw identifiers."""
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError(f"API rate-limit {dimension} value must not be blank.")
        # Only the digest reaches Redis or in-memory limiter storage.
        digest = self._hashing.digest(
            normalized_value,
            namespace=f"api-rate-limit:{dimension}",
        )
        return f"api:{operation}:{dimension}:{digest}"


def _normalize_operation(value: str) -> str:
    """Normalize an internal route operation used in backend keys."""
    normalized = value.strip().casefold().replace(" ", "-")
    if not normalized:
        raise ValueError("API rate-limit operation must not be blank.")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("API rate-limit operation contains invalid control characters.")
    return normalized


__all__ = ["APIRateLimits"]
