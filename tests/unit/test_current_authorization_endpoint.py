"""Single current-user authorization endpoint tests."""

from __future__ import annotations

import json
import uuid

import pytest
from app.auth.request_context.principals import UserPrincipal
from app.modules.current_user.routes import get_current_authorization


@pytest.mark.asyncio
async def test_current_authorization_returns_sorted_database_principal_data() -> None:
    principal = UserPrincipal(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        roles=frozenset({"doctor", "customer"}),
        permissions=frozenset({"orders.read", "clinical.prescriptions.issue"}),
        auth_methods=("password",),
    )

    response = await get_current_authorization(principal=principal)
    body = json.loads(response.body)

    assert body["data"]["roles"] == ["customer", "doctor"]
    assert body["data"]["permissions"] == [
        "clinical.prescriptions.issue",
        "orders.read",
    ]
