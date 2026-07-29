from __future__ import annotations

import pytest

from app.common.exceptions import RateLimitError
from app.core.rate_limiting import InMemoryRateLimiter, enforce_rate_limit
from app.auth.context import AuthRequestContext
from app.auth.rate_limits import AuthRateLimits
from app.auth.security.hashing import SecureHashing
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
