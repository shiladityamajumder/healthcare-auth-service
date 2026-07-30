"""File: tests/unit/test_auth_rate_limits.py"""

from __future__ import annotations

import uuid

import pytest
from app.auth.api_rate_limits import APIRateLimits
from app.auth.request_context.context import AuthRequestContext
from app.auth.request_context.principals import UserPrincipal
from app.auth.security.hashing import SecureHashing
from app.auth.security_policy import RateLimitPolicy, RouteSecurityPolicy
from app.auth.workflows.rate_limits import AuthRateLimits
from app.common.exceptions import RateLimitError
from app.core.rate_limiting import InMemoryRateLimiter, enforce_rate_limit
from tests.conftest import build_test_settings


@pytest.mark.asyncio
async def test_in_memory_rate_limiter_blocks_after_limit() -> None:
    limiter = InMemoryRateLimiter()
    await enforce_rate_limit(limiter, keys=["login:test"], limit=2, window_seconds=60)
    await enforce_rate_limit(limiter, keys=["login:test"], limit=2, window_seconds=60)
    with pytest.raises(RateLimitError):
        await enforce_rate_limit(limiter, keys=["login:test"], limit=2, window_seconds=60)


class RecordingLimiter:
    def __init__(self) -> None:
        self.keys: list[str] = []

    async def hit(self, *, key: str, limit: int, window_seconds: int):
        from app.core.rate_limiting import RateLimitDecision

        _ = limit, window_seconds
        self.keys.append(key)
        return RateLimitDecision(allowed=True, remaining=1, retry_after_seconds=0)

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_auth_rate_limit_keys_do_not_contain_raw_identity() -> None:
    settings = build_test_settings()
    limiter = RecordingLimiter()
    policy = AuthRateLimits(
        settings=settings,
        limiter=limiter,
        hashing=SecureHashing(settings),
    )
    identity = "user@example.com"
    await policy.login(
        context=AuthRequestContext(
            ip_address="203.0.113.10",
            user_agent="test",
            request_id=None,
            device_id="device-123",
        ),
        identity=identity,
    )
    assert len(limiter.keys) == 3
    assert all(identity not in key for key in limiter.keys)
    assert all("203.0.113.10" not in key for key in limiter.keys)


@pytest.mark.asyncio
async def test_api_rate_limits_hash_principal_and_origin_dimensions() -> None:
    settings = build_test_settings()
    limiter = RecordingLimiter()
    policy = APIRateLimits(
        settings=settings,
        limiter=limiter,
        hashing=SecureHashing(settings),
    )
    principal = UserPrincipal(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
    )
    context = AuthRequestContext(
        ip_address="203.0.113.11",
        client_id="web-client",
        device_id="device-456",
    )

    await policy.enforce(
        policy=RateLimitPolicy.ADMIN_WRITE,
        operation="update_user_status",
        context=context,
        principal=principal,
    )

    assert len(limiter.keys) == 4
    raw_values = {
        str(principal.user_id),
        "203.0.113.11",
        "web-client",
        "device-456",
    }
    assert all(raw not in key for raw in raw_values for key in limiter.keys)
    assert all(key.startswith("api:update_user_status:") for key in limiter.keys)


@pytest.mark.asyncio
async def test_api_rate_limit_none_is_an_explicit_per_route_switch() -> None:
    settings = build_test_settings()
    limiter = RecordingLimiter()
    policy = APIRateLimits(
        settings=settings,
        limiter=limiter,
        hashing=SecureHashing(settings),
    )

    await policy.enforce(
        policy=RateLimitPolicy.NONE,
        operation="public_metadata",
        context=AuthRequestContext(ip_address="203.0.113.12"),
    )

    assert limiter.keys == []


def test_public_route_policy_cannot_require_authorization_claims() -> None:
    """Public policies must not imply authorization without authentication."""
    with pytest.raises(
        ValueError,
        match="Public route policies cannot require permissions or roles",
    ):
        RouteSecurityPolicy(
            authentication_required=False,
            permissions=frozenset({"identity.users.read"}),
        )
