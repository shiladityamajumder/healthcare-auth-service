"""Public authentication capability endpoint tests."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from app.modules.capabilities.routes import get_auth_capabilities
from tests.conftest import build_test_settings


@pytest.mark.asyncio
async def test_public_capabilities_are_safe_and_cacheable() -> None:
    runtime = SimpleNamespace(settings=build_test_settings())

    response = await get_auth_capabilities(
        runtime=cast(Any, runtime),
        if_none_match=None,
    )
    body = json.loads(response.body)
    serialized = response.body.decode("utf-8").casefold()

    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    assert response.headers["etag"].startswith('"')
    assert body["data"]["schema"] == "auth-capabilities"
    assert body["data"]["passwordPolicy"]["minimumLength"] == 12
    assert '"roles"' not in serialized
    assert '"permissions"' not in serialized
    assert "jwt" not in serialized

    not_modified = await get_auth_capabilities(
        runtime=cast(Any, runtime),
        if_none_match=response.headers["etag"],
    )
    assert not_modified.status_code == 304
