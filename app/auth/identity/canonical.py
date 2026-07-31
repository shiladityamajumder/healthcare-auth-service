"""File: app/auth/identity/canonical.py

Purpose:
Builds stable canonical email, phone, and channel-aware identity strings for
security workflows.

Dependency flow:
Validated identity input
-> normalization helper
-> canonical identity string
-> lookup, duplicate check, OTP, audit, or rate-limit consumer

This module converts email, phone, and channel-aware identity inputs into
stable canonical strings.

Canonical identities are suitable for:

* Authentication lookups.
* Rate-limit key generation.
* OTP destination hashing.
* Duplicate-account detection.
* Security audit correlation.

This module does not hash identities and does not access persistence. Callers
that require irreversible identifiers should pass the returned canonical value
to ``SecureHashing`` or another approved hashing boundary.
"""

from __future__ import annotations

from typing import Protocol

from app.auth.identity.normalization import (
    normalize_email,
    normalize_phone,
    phone_destination,
)
from app.models.enums import OTPChannel


class ChannelIdentityPayload(Protocol):
    """Channel-aware identity fields required by ``generic_identity``.

    Request DTOs may satisfy this protocol structurally without inheriting
    from it.
    """

    channel: OTPChannel | str
    email: object | None
    phone_country_code: object | None
    phone_number: object | None


def email_identity(
    value: object,
) -> str:
    """Return a canonical email identity.

    Args:
        value: Email-like value supplied by a request or service.

    Returns:
        Normalized email address.

    Raises:
        ValueError: If the value is absent, blank, or rejected by the email
            normalization rules.
    """
    email = _required_text(
        value,
        field_name="email",
    )

    return normalize_email(email)


def phone_identity(
    country_code: object,
    phone_number: object,
) -> str:
    """Return a canonical phone identity.

    The country code and national phone number are normalized independently
    and then composed into the canonical phone destination format used by the
    authentication service.

    Args:
        country_code: Phone country code, with or without a leading plus sign.
        phone_number: National phone number.

    Returns:
        Canonical E.164-like phone destination.

    Raises:
        ValueError: If either value is absent, blank, or rejected by the phone
            normalization rules.
    """
    raw_country_code = _required_text(
        country_code,
        field_name="phone_country_code",
    )
    raw_phone_number = _required_text(
        phone_number,
        field_name="phone_number",
    )

    normalized_country_code, normalized_phone_number = normalize_phone(
        raw_country_code,
        raw_phone_number,
    )

    return phone_destination(
        normalized_country_code,
        normalized_phone_number,
    )


def generic_identity(
    payload: ChannelIdentityPayload,
) -> str:
    """Resolve a canonical identity from a channel-aware payload.

    Email channels require ``payload.email``. SMS channels require
    ``payload.phone_country_code`` and ``payload.phone_number``.

    Args:
        payload: Structurally compatible request or command object.

    Returns:
        Canonical email or phone identity.

    Raises:
        ValueError: If the channel is unsupported or required identity fields
            are missing or invalid.
    """
    channel = _normalize_channel(payload.channel)

    if channel is OTPChannel.EMAIL:
        return email_identity(payload.email)

    if channel is OTPChannel.SMS:
        return phone_identity(
            payload.phone_country_code,
            payload.phone_number,
        )

    # All current OTPChannel values are handled above. This branch protects
    # against future enum additions that have not yet been implemented.
    raise ValueError(f"Unsupported identity channel: {channel.value}")


def _normalize_channel(
    value: OTPChannel | str,
) -> OTPChannel:
    """Normalize and validate an identity channel.

    Args:
        value: OTP channel enum or string value.

    Returns:
        Validated OTP channel.

    Raises:
        ValueError: If the channel is blank or unsupported.
    """
    if isinstance(value, OTPChannel):
        return value

    normalized = _required_text(
        value,
        field_name="channel",
    ).lower()

    try:
        return OTPChannel(normalized)
    except ValueError as exc:
        raise ValueError(f"Unsupported identity channel: {value}") from exc


def _required_text(
    value: object,
    *,
    field_name: str,
) -> str:
    """Convert a required scalar-like value into nonblank text.

    Args:
        value: Value requiring normalization.
        field_name: Field name used in validation errors.

    Returns:
        Trimmed nonblank string.

    Raises:
        ValueError: If the value is absent or blank.
    """
    if value is None:
        raise ValueError(f"{field_name} is required.")

    normalized = str(value).strip()

    if not normalized:
        raise ValueError(f"{field_name} is required.")

    return normalized


__all__ = [
    "ChannelIdentityPayload",
    "email_identity",
    "generic_identity",
    "phone_identity",
]
