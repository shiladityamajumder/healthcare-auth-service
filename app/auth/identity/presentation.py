"""File: app/auth/identity/presentation.py

Purpose:
Builds masked identity values and public user projections for authorized API
responses and notification workflows.

Dependency flow:
Normalized identity or Users ORM instance
-> masking/public projection helper
-> response schema or notification-safe value

This module creates masked identity values suitable for API responses,
notifications, account-recovery responses, support workflows, and security
logs.

Masking reduces accidental exposure but is not anonymization, encryption, or
authorization. Callers must still ensure that identity information is exposed
only to an authorized recipient.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.auth.identity.normalization import (
    normalize_email,
    normalize_phone,
)


def admin_user_data(
    user: Any,
    *,
    profile: Any | None = None,
    roles: Iterable[str] = (),
    permissions: Iterable[str] = (),
) -> dict[str, object]:
    """Build an administrative user representation with authorization data.

    Password hashes, lockout counters, and other internal account state are
    intentionally excluded. Authorization codes are sorted so responses are
    deterministic when callers supply sets or database-derived collections.
    """
    data = authenticated_user_data(
        user,
        profile=profile,
    )
    data.update(
        {
            "roles": sorted(set(roles)),
            "permissions": sorted(set(permissions)),
        }
    )
    return data


def authenticated_user_data(
    user: Any,
    *,
    profile: Any | None = None,
) -> dict[str, object]:
    """Build a minimal authenticated profile without authorization lists."""
    phone_number_masked = None
    if user.phone_country_code is not None and user.phone_number is not None:
        phone_number_masked = mask_phone(
            user.phone_country_code,
            user.phone_number,
        )

    status = getattr(user.status, "value", user.status)
    profile_data: dict[str, object] | None = None
    if profile is not None:
        profile_data = {
            "first_name": profile.first_name,
            "last_name": profile.last_name,
            "preferred_name": profile.preferred_name,
            "avatar_file_id": profile.avatar_file_id,
        }

    # Prefer profile names but always provide a stable fallback for identities
    # that have not completed an optional profile.
    preferred_name = _nonblank(getattr(profile, "preferred_name", None))
    first_name = _nonblank(getattr(profile, "first_name", None))
    last_name = _nonblank(getattr(profile, "last_name", None))
    combined_name = " ".join(value for value in (first_name, last_name) if value)
    display_name = (
        preferred_name or combined_name or user.email or phone_number_masked or str(user.id)[:8]
    )

    return {
        "id": user.id,
        "email": user.email,
        "email_verified": user.email_verified_at is not None,
        "phone_country_code": user.phone_country_code,
        "phone_number_masked": phone_number_masked,
        "phone_verified": user.phone_verified_at is not None,
        "status": status,
        "preferred_locale": user.preferred_locale,
        "timezone": user.timezone,
        "display_name": display_name,
        "profile": profile_data,
    }


def _nonblank(value: object) -> str | None:
    """Return a stripped string or ``None`` for missing/blank profile values."""
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def mask_email(
    value: str,
) -> str:
    """Normalize and mask an email address.

    Examples:
        ``alice@example.com`` becomes ``al***@example.com``.
        ``a@example.com`` becomes ``a***@example.com``.

    Args:
        value: Email address to normalize and mask.

    Returns:
        Masked normalized email address.

    Raises:
        ValidationError: If the email address is invalid.
    """
    normalized_email = normalize_email(value)

    local_part, separator, domain = normalized_email.partition("@")

    if not separator or not local_part or not domain:
        return "***"

    visible_length = 1 if len(local_part) == 1 else 2
    visible_part = local_part[:visible_length]

    hidden_length = max(
        len(local_part) - visible_length,
        3,
    )

    return f"{visible_part}{'*' * hidden_length}@{domain}"


def mask_phone(
    country_code: str,
    phone_number: str,
) -> str:
    """Normalize and mask a phone number.

    The normalized country code and final four national-number digits remain
    visible.

    Example:
        ``+91`` and ``9876543210`` become ``+91******3210``.

    Args:
        country_code: International calling code.
        phone_number: National phone number.

    Returns:
        Masked normalized phone destination.

    Raises:
        ValidationError: If either phone component is invalid.
    """
    normalized_country_code, normalized_phone_number = normalize_phone(
        country_code,
        phone_number,
    )

    visible_suffix_length = min(
        4,
        len(normalized_phone_number),
    )
    visible_suffix = normalized_phone_number[-visible_suffix_length:]

    hidden_length = max(
        len(normalized_phone_number) - visible_suffix_length,
        2,
    )

    return f"{normalized_country_code}{'*' * hidden_length}{visible_suffix}"


__all__ = [
    "admin_user_data",
    "authenticated_user_data",
    "mask_email",
    "mask_phone",
]
