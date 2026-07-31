"""File: tests/unit/test_auth_headers.py

Purpose:
Verifies request identifiers, typed authentication metadata, and trusted-proxy
client address handling.

Dependency flow:
Synthetic request or TestClient call
-> middleware/header/context parsing
-> AuthRequestContext or response headers
-> security assertions
"""

from __future__ import annotations

import uuid
from typing import Any, cast

import pytest
from app.auth.request_context.context import AuthRequestContext
from app.auth.request_context.dependencies import get_current_user_principal
from app.auth.request_context.headers import AuthHeaders
from app.common.exceptions import AuthenticationError
from app.main import create_app
from fastapi.testclient import TestClient
from starlette.requests import Request
from tests.conftest import build_test_settings


def test_request_id_is_generated_and_returned() -> None:
    """Require middleware to create and return missing request identifiers."""
    app = create_app(build_test_settings())
    response = TestClient(app).get("/health/live")
    assert response.status_code == 200
    assert uuid.UUID(response.headers["X-Request-ID"])
    assert response.headers["X-Correlation-ID"] == response.headers["X-Request-ID"]


def test_valid_request_and_correlation_ids_are_echoed() -> None:
    """Preserve valid caller correlation identifiers through the response."""
    request_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())
    app = create_app(build_test_settings())
    response = TestClient(app).get(
        "/health/live",
        headers={
            "X-Request-ID": request_id,
            "X-Correlation-ID": correlation_id,
        },
    )
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == request_id
    assert response.headers["X-Correlation-ID"] == correlation_id


def test_invalid_request_id_is_rejected_before_route_execution() -> None:
    """Reject malformed request identifiers at the middleware boundary."""
    app = create_app(build_test_settings())
    response = TestClient(app).get(
        "/health/live",
        headers={"X-Request-ID": "not-a-uuid"},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "INVALID_REQUEST_ID"
    assert uuid.UUID(response.headers["X-Request-ID"])


def test_forwarded_for_is_used_only_for_trusted_proxy() -> None:
    """Prevent untrusted peers from spoofing the client address header."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", b"203.0.113.9, 10.0.0.2")],
        "client": ("10.0.0.2", 12345),
        "server": ("testserver", 80),
        "scheme": "http",
        "query_string": b"",
        "root_path": "",
        "http_version": "1.1",
    }
    request = Request(scope)
    untrusted = AuthRequestContext.from_request(
        request,
        settings=build_test_settings(),
        headers=AuthHeaders(),
    )
    trusted = AuthRequestContext.from_request(
        request,
        settings=build_test_settings(
            TRUSTED_PROXY_ENABLED=True,
            TRUSTED_PROXY_CIDRS=["10.0.0.0/8"],
        ),
        headers=AuthHeaders(),
    )
    assert untrusted.ip_address == "10.0.0.2"
    assert trusted.ip_address == "203.0.113.9"


@pytest.mark.asyncio
async def test_missing_authentication_cannot_be_replaced_by_identity_headers() -> None:
    """Reject custom identity/authorization assertions without a bearer token."""
    context = AuthRequestContext(
        asserted_user_id=uuid.uuid4(),
        asserted_session_id=uuid.uuid4(),
        device_id="attacker-device",
    )

    with pytest.raises(AuthenticationError):
        await get_current_user_principal(
            credentials=None,
            database=cast(Any, object()),
            runtime=cast(Any, object()),
            context=context,
        )
