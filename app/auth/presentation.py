"""Safe mapping helpers shared by identity modules."""

from __future__ import annotations

from typing import Any

from app.auth.normalization import mask_phone
from app.models.identity import Users


def public_user_data(
    user: Users,
    *,
    roles: list[str],
    permissions: list[str],
) -> dict[str, Any]:
    """Map a user record to non-sensitive public identity fields."""
    phone_masked = None
    if user.phone_country_code and user.phone_number:
        phone_masked = mask_phone(user.phone_country_code, user.phone_number)
    return {
        "id": user.id,
        "email": user.email,
        "email_verified": user.email_verified_at is not None,
        "phone_country_code": user.phone_country_code,
        "phone_number_masked": phone_masked,
        "phone_verified": user.phone_verified_at is not None,
        "status": user.status.value if hasattr(user.status, "value") else str(user.status),
        "preferred_locale": user.preferred_locale,
        "timezone": user.timezone,
        "roles": roles,
        "permissions": permissions,
    }


__all__ = ["public_user_data"]
