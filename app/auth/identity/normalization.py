"""File: app/auth/identity/normalization.py

Purpose:
Validates and normalizes email addresses, country codes, and national phone
numbers into the database-compatible identity form.

Dependency flow:
Schema/service identity input
-> validation and normalization
-> canonical database lookup value
-> repository or canonical identity builder

This module defines the canonical normalization rules used for email addresses,
phone country codes, and national phone numbers.

Normalized identities are suitable for:

* Database lookup and normalized identity columns.
* Duplicate-account detection.
* OTP destination construction.
* Rate-limit identity construction.
* Security event correlation.

This module does not perform masking, hashing, persistence, or transport-layer
validation. Presentation-safe masking belongs in
``app.auth.identity.presentation``.
"""

from __future__ import annotations

import re
from typing import Final

from email_validator import (
    EmailNotValidError,
    validate_email,
)

from app.common.exceptions import ValidationError

_COUNTRY_CODE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\+[1-9][0-9]{0,2}$")

_NATIONAL_PHONE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9]{6,14}$")

_PHONE_FORMATTING_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\s().-]+")

_E164_MIN_DIGITS: Final[int] = 7
_E164_MAX_DIGITS: Final[int] = 15


def normalize_email(
    value: str,
) -> str:
    """Validate and normalize an email address.

    Validation is syntactic only. DNS and mailbox deliverability checks are
    intentionally disabled because normalization must remain deterministic and
    must not perform external network calls.

    The final value is case-folded because this authentication service treats
    email identities as case-insensitive for lookup and uniqueness.

    Args:
        value: Email address supplied by a request or stored record.

    Returns:
        Canonical case-insensitive email identity.

    Raises:
        ValidationError: If the email is blank or syntactically invalid.
    """
    normalized_input = value.strip()

    if not normalized_input:
        raise ValidationError("The email address is required.")

    try:
        validation = validate_email(
            normalized_input,
            check_deliverability=False,
        )
    except EmailNotValidError as exc:
        raise ValidationError("The email address is invalid.") from exc

    return validation.normalized.casefold()


def normalize_country_code(
    value: str,
) -> str:
    """Normalize and validate an international calling code.

    Spaces are removed and a leading plus sign is added when omitted.

    Args:
        value: Country calling code such as ``91`` or ``+91``.

    Returns:
        Canonical calling code including the leading plus sign.

    Raises:
        ValidationError: If the value is blank or structurally invalid.
    """
    normalized = value.strip().replace(" ", "")

    if not normalized:
        raise ValidationError("The phone country code is required.")

    if not normalized.startswith("+"):
        normalized = f"+{normalized}"

    if not _COUNTRY_CODE_PATTERN.fullmatch(normalized):
        raise ValidationError("The phone country code is invalid.")

    return normalized


def normalize_phone_number(
    value: str,
) -> str:
    """Normalize and validate a national phone number.

    Common display formatting characters are removed. The country calling code
    must be supplied separately.

    Args:
        value: National phone number.

    Returns:
        Digits-only national phone number.

    Raises:
        ValidationError: If the value is blank, includes a leading country
            code marker, contains unsupported characters, or has an invalid
            length.
    """
    stripped_value = value.strip()

    if not stripped_value:
        raise ValidationError("The phone number is required.")

    if stripped_value.startswith("+"):
        raise ValidationError("Provide the country code separately from the phone number.")

    normalized = _PHONE_FORMATTING_PATTERN.sub(
        "",
        stripped_value,
    )

    if not _NATIONAL_PHONE_PATTERN.fullmatch(normalized):
        raise ValidationError("The phone number is invalid.")

    return normalized


def normalize_phone(
    country_code: str,
    phone_number: str,
) -> tuple[str, str]:
    """Normalize and validate a country-code and phone-number pair.

    In addition to validating the two components independently, the combined
    destination is checked against the E.164 maximum length.

    Args:
        country_code: International country calling code.
        phone_number: National phone number.

    Returns:
        Tuple containing the normalized country code and national number.

    Raises:
        ValidationError: If either component or the combined destination is
            invalid.
    """
    normalized_country_code = normalize_country_code(country_code)
    normalized_phone_number = normalize_phone_number(phone_number)

    total_digits = len(normalized_country_code) - 1 + len(normalized_phone_number)

    if not _E164_MIN_DIGITS <= total_digits <= _E164_MAX_DIGITS:
        raise ValidationError("The complete phone number is invalid.")

    return (
        normalized_country_code,
        normalized_phone_number,
    )


def phone_destination(
    country_code: str,
    phone_number: str,
) -> str:
    """Build a canonical E.164-like phone destination.

    Args:
        country_code: International country calling code.
        phone_number: National phone number.

    Returns:
        Canonical phone destination such as ``+919876543210``.

    Raises:
        ValidationError: If the phone components are invalid.
    """
    normalized_country_code, normalized_phone_number = normalize_phone(
        country_code,
        phone_number,
    )

    return f"{normalized_country_code}{normalized_phone_number}"


__all__ = [
    "normalize_country_code",
    "normalize_email",
    "normalize_phone",
    "normalize_phone_number",
    "phone_destination",
]
