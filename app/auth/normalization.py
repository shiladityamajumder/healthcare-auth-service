"""Shared authentication normalization infrastructure."""

from __future__ import annotations

import re

from app.common.exceptions import ValidationError

_PHONE_PATTERN = re.compile(r"^[0-9]{6,20}$")
_COUNTRY_PATTERN = re.compile(r"^\+[1-9][0-9]{0,3}$")


def normalize_email(value: str) -> str:
    """Normalize an email address for comparison and storage."""
    return value.strip().casefold()


def normalize_country_code(value: str) -> str:
    """Normalize an international phone country code."""
    normalized = value.strip().replace(" ", "")
    if not normalized.startswith("+"):
        normalized = f"+{normalized}"
    if not _COUNTRY_PATTERN.fullmatch(normalized):
        raise ValidationError("The phone country code is invalid.")
    return normalized


def normalize_phone_number(value: str) -> str:
    """Normalize a national phone number to digits only."""
    normalized = re.sub(r"[\s().-]", "", value.strip())
    if normalized.startswith("+"):
        raise ValidationError("Provide the country code separately from the phone number.")
    if not _PHONE_PATTERN.fullmatch(normalized):
        raise ValidationError("The phone number is invalid.")
    return normalized


def normalize_phone(country_code: str, phone_number: str) -> tuple[str, str]:
    """Normalize and validate a country code and phone-number pair."""
    return normalize_country_code(country_code), normalize_phone_number(phone_number)


def phone_destination(country_code: str, phone_number: str) -> str:
    """Build the canonical phone destination used by OTP workflows."""
    country, number = normalize_phone(country_code, phone_number)
    return f"{country}{number}"


def mask_email(value: str) -> str:
    """Mask an email address for safe display."""
    local, separator, domain = value.partition("@")
    if not separator:
        return "***"
    visible = local[:2]
    return f"{visible}{'*' * max(len(local) - 2, 3)}@{domain}"


def mask_phone(country_code: str, phone_number: str) -> str:
    """Mask a phone number for safe display."""
    return f"{country_code}{'*' * max(len(phone_number) - 4, 2)}{phone_number[-4:]}"


__all__ = [
    "mask_email",
    "mask_phone",
    "normalize_country_code",
    "normalize_email",
    "normalize_phone",
    "normalize_phone_number",
    "phone_destination",
]
