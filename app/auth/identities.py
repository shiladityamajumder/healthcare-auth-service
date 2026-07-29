"""Canonical identity normalization helpers for rate-limit keys."""

from __future__ import annotations

from app.auth.normalization import normalize_email, normalize_phone, phone_destination


def email_identity(value: object) -> str:
    """Return a normalized email identity."""
    return normalize_email(str(value))


def phone_identity(country_code: str, phone_number: str) -> str:
    """Return a normalized E.164-like phone destination."""
    country, phone = normalize_phone(country_code, phone_number)
    return phone_destination(country, phone)


def generic_identity(payload: object) -> str:
    """Resolve an email or phone identity from a channel-aware DTO."""
    channel = str(getattr(payload, "channel", ""))
    if channel == "email":
        return email_identity(getattr(payload, "email"))
    return phone_identity(
        str(getattr(payload, "phone_country_code")),
        str(getattr(payload, "phone_number")),
    )


__all__ = ["email_identity", "generic_identity", "phone_identity"]
