"""File: tests/unit/test_auth_notifications.py

Purpose:
Verifies the deliberate fail-closed notification-delivery boundary.

Dependency flow:
Test notification call
-> NotificationDispatcher
-> disabled gateway
-> expected infrastructure exception
"""

from __future__ import annotations

import pytest

from app.auth.workflows.notifications import NotificationDispatcher


class RecordingNotificationGateway:
    def __init__(self) -> None:
        self.called = False

    async def send_otp(self, **kwargs: object) -> None:
        _ = kwargs
        self.called = True


@pytest.mark.asyncio
async def test_notification_delivery_is_intentionally_disabled() -> None:
    gateway = RecordingNotificationGateway()
    dispatcher = NotificationDispatcher(gateway)
    await dispatcher.send_otp(
        channel="email",
        destination="user@example.com",
        code="123456",
        purpose="verify_email",
        expires_in_seconds=300,
    )
    assert gateway.called is False
