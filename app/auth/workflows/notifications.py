"""File: app/auth/workflows/notifications.py

Purpose:
Defines the authentication notification port and the currently disabled
delivery gateway used by OTP-producing workflows.

Dependency flow:
Authentication service after persistence decision
-> AuthNotificationGateway
-> NotificationDispatcher implementation
-> external provider when configured, otherwise disabled boundary

External delivery remains intentionally disabled until the platform
notification service is connected.

Authentication workflows may call this boundary at the correct transaction
boundary without knowing whether notifications are delivered by email, SMS,
a queue, or an external service.

Plaintext OTP values and complete destinations must never be written to logs.
"""

from __future__ import annotations

from typing import Protocol

from app.core.config import AppSettings
from app.core.logging import get_logger

logger = get_logger(__name__)


class NotificationService(Protocol):
    """Port implemented by an email or SMS notification adapter."""

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
    """Disabled authentication notification gateway.

    Authentication workflows can safely call this gateway now. It validates
    notification metadata and records only non-sensitive operational metadata.

    External delivery must be implemented here later without changing the
    calling authentication workflows.
    """

    def __init__(
        self,
        settings: AppSettings,
    ) -> None:
        """Initialize the notification boundary.

        Args:
            settings: Validated application settings reserved for the future
                notification-service integration.
        """
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
        """Validate and prepare an OTP notification.

        External delivery is intentionally disabled. Neither the plaintext OTP
        nor the complete destination is logged.

        Args:
            channel: Notification channel, such as email or SMS.
            destination: Canonical email address or phone destination.
            code: Plaintext OTP intended for the recipient.
            purpose: Authentication workflow purpose.
            expires_in_seconds: Number of seconds before the OTP expires.

        Raises:
            ValueError: If required notification metadata is invalid.
        """
        normalized_channel = _required_text(
            channel,
            field_name="channel",
            casefold=True,
        )
        normalized_purpose = _required_text(
            purpose,
            field_name="purpose",
            casefold=True,
        )

        _required_text(
            destination,
            field_name="destination",
        )
        _required_text(
            code,
            field_name="code",
        )

        if expires_in_seconds <= 0:
            raise ValueError(
                "expires_in_seconds must be greater than zero."
            )

        # Keep the settings reference because the future adapter will use
        # notification-service configuration, credentials, and timeouts.
        _ = self._settings

        logger.info(
            "Authentication notification prepared",
            extra={
                "channel": normalized_channel,
                "purpose": normalized_purpose,
                "expires_in_seconds": expires_in_seconds,
                "delivery_enabled": False,
            },
        )

        # Future integration:
        #
        # await notification_client.send_otp(
        #     channel=normalized_channel,
        #     destination=destination,
        #     code=code,
        #     purpose=normalized_purpose,
        #     expires_in_seconds=expires_in_seconds,
        # )
        #
        # Never log destination, code, authorization headers, provider
        # credentials, or complete provider responses.


class NotificationDispatcher:
    """Conditionally dispatch notifications through an injected gateway.

    Delivery is disabled by default. Existing callers therefore remain safe
    until the notification-service integration is explicitly enabled.
    """

    def __init__(
        self,
        gateway: NotificationService,
        *,
        enabled: bool = False,
    ) -> None:
        """Initialize the dispatcher.

        Args:
            gateway: Notification delivery implementation.
            enabled: Whether the gateway may perform external delivery.
        """
        self._gateway = gateway
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        """Return whether external notification dispatch is enabled."""
        return self._enabled

    async def send_otp(
        self,
        *,
        channel: str,
        destination: str,
        code: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> None:
        """Dispatch an OTP only when delivery is explicitly enabled.

        Args:
            channel: Notification channel.
            destination: Canonical destination.
            code: Plaintext OTP.
            purpose: Authentication workflow purpose.
            expires_in_seconds: OTP lifetime in seconds.
        """
        if not self._enabled:
            logger.info(
                "Authentication notification dispatch skipped",
                extra={
                    "channel": channel.strip().casefold(),
                    "purpose": purpose.strip().casefold(),
                    "expires_in_seconds": expires_in_seconds,
                    "delivery_enabled": False,
                },
            )
            return

        await self._gateway.send_otp(
            channel=channel,
            destination=destination,
            code=code,
            purpose=purpose,
            expires_in_seconds=expires_in_seconds,
        )


def _required_text(
    value: str,
    *,
    field_name: str,
    casefold: bool = False,
) -> str:
    """Normalize one required notification value."""
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

    if casefold:
        normalized = normalized.casefold()

    return normalized


__all__ = [
    "AuthNotificationGateway",
    "NotificationDispatcher",
    "NotificationService",
]
