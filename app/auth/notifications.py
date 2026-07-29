"""Authentication notification integration boundary.

Delivery remains intentionally disabled until the platform notification service
is connected. Workflows still call this boundary at the correct transaction
boundary, without logging OTP codes or full destinations.
"""

from __future__ import annotations

from typing import Protocol

from app.core.config import AppSettings
from app.core.logging import get_logger

logger = get_logger(__name__)


class NotificationService(Protocol):
    """Port implemented by an email/SMS notification adapter."""

    async def send_otp(
        self,
        *,
        channel: str,
        destination: str,
        code: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> None:
        """Deliver an OTP through the configured notification channel."""
        ...


class AuthNotificationGateway:
    """Future outbound adapter for authentication notifications."""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings

    async def send_otp(
        self,
        *,
        channel: str,
        destination: str,
        code: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> None:
        """Prepare notification metadata without exposing sensitive values."""
        # Future notification-service integration belongs here. Never log the
        # destination or plaintext OTP code.
        _ = destination, code, self._settings
        logger.info(
            "Authentication notification prepared",
            extra={
                "channel": channel,
                "purpose": purpose,
                "expires_in_seconds": expires_in_seconds,
                "delivery_enabled": False,
            },
        )


class NotificationDispatcher:
    """Application boundary that can be enabled without changing use cases."""

    def __init__(self, gateway: NotificationService) -> None:
        self._gateway = gateway

    async def send_otp(
        self,
        *,
        channel: str,
        destination: str,
        code: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> None:
        """Keep external delivery disabled during the current build phase."""
        # await self._gateway.send_otp(
        #     channel=channel,
        #     destination=destination,
        #     code=code,
        #     purpose=purpose,
        #     expires_in_seconds=expires_in_seconds,
        # )
        _ = (
            self._gateway,
            channel,
            destination,
            code,
            purpose,
            expires_in_seconds,
        )


__all__ = [
    "AuthNotificationGateway",
    "NotificationDispatcher",
    "NotificationService",
]
