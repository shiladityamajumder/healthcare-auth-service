"""File: app/utils/datetime_utils.py
Timezone-aware datetime utilities.

The configured application timezone is the authoritative timezone for
application-facing dates and times. UTC remains the canonical timezone for
database persistence, event timestamps, distributed systems, and external
service communication.

All public helpers reject timezone-naive datetime values to prevent ambiguous
comparisons and incorrect timezone conversion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from zoneinfo import ZoneInfo

from app.core.config import get_settings


@lru_cache(maxsize=1)
def application_timezone() -> ZoneInfo:
    """Return the configured application timezone.

    The timezone is loaded from the validated application configuration and
    cached for the process lifetime.

    Returns:
        Configured IANA timezone.

    Raises:
        ZoneInfoNotFoundError: If an invalid timezone bypasses configuration
            validation.
    """
    return ZoneInfo(get_settings().TIMEZONE)


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime.

    UTC should be used for persistence, distributed events, audit timestamps,
    expiration storage, and communication between services.

    Returns:
        Current timezone-aware UTC datetime.
    """
    return datetime.now(UTC)


def current_datetime() -> datetime:
    """Return the current datetime in the configured application timezone.

    Returns:
        Current timezone-aware application-local datetime.
    """
    return datetime.now(application_timezone())


def require_aware(value: datetime) -> datetime:
    """Validate that a datetime contains effective timezone information.

    Args:
        value: Datetime value to validate.

    Returns:
        The original timezone-aware datetime.

    Raises:
        ValueError: If the datetime is timezone-naive or has no effective UTC
            offset.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timezone-naive datetimes are not allowed")

    return value


def to_utc(value: datetime) -> datetime:
    """Convert a timezone-aware datetime to UTC.

    Args:
        value: Timezone-aware datetime.

    Returns:
        Equivalent datetime in UTC.

    Raises:
        ValueError: If ``value`` is timezone-naive.
    """
    return require_aware(value).astimezone(UTC)


def to_application_timezone(value: datetime) -> datetime:
    """Convert a timezone-aware datetime to the configured timezone.

    Args:
        value: Timezone-aware datetime.

    Returns:
        Equivalent datetime in the configured application timezone.

    Raises:
        ValueError: If ``value`` is timezone-naive.
    """
    return require_aware(value).astimezone(application_timezone())


def datetime_to_iso(
    value: datetime,
    *,
    use_application_timezone: bool = False,
) -> str:
    """Serialize a timezone-aware datetime as ISO 8601.

    By default, the value retains its current timezone. Set
    ``use_application_timezone`` to convert it to the configured application
    timezone before serialization.

    Args:
        value: Timezone-aware datetime.
        use_application_timezone: Whether to convert the value to the configured
            application timezone before serialization.

    Returns:
        ISO 8601 datetime string.

    Raises:
        ValueError: If ``value`` is timezone-naive.
    """
    aware_value = require_aware(value)

    if use_application_timezone:
        aware_value = to_application_timezone(aware_value)

    return aware_value.isoformat()


def datetime_to_utc_iso(value: datetime) -> str:
    """Serialize a timezone-aware datetime as a UTC ISO 8601 string.

    The UTC offset is represented using the conventional ``Z`` suffix.

    Args:
        value: Timezone-aware datetime.

    Returns:
        UTC ISO 8601 datetime string.

    Raises:
        ValueError: If ``value`` is timezone-naive.
    """
    return to_utc(value).isoformat().replace("+00:00", "Z")


def parse_iso_datetime(
    value: str,
    *,
    convert_to_application_timezone: bool = False,
) -> datetime:
    """Parse an ISO 8601 datetime with mandatory timezone information.

    The parser accepts both explicit UTC offsets and the ``Z`` suffix.

    Args:
        value: ISO 8601 datetime string.
        convert_to_application_timezone: Whether to convert the parsed datetime
            to the configured application timezone.

    Returns:
        Parsed timezone-aware datetime.

    Raises:
        ValueError: If the value is blank, malformed, or timezone-naive.
    """
    normalized = value.strip()

    if not normalized:
        raise ValueError("Datetime value must not be blank")

    if normalized.endswith(("Z", "z")):
        normalized = f"{normalized[:-1]}+00:00"

    parsed = require_aware(datetime.fromisoformat(normalized))

    if convert_to_application_timezone:
        return to_application_timezone(parsed)

    return parsed


def is_expired(
    expiry: datetime,
    *,
    now: datetime | None = None,
) -> bool:
    """Return whether an expiry datetime has passed.

    Comparisons are normalized to UTC to avoid timezone-dependent comparison
    errors. When ``now`` is omitted, the current UTC time is used.

    Args:
        expiry: Timezone-aware expiration datetime.
        now: Optional timezone-aware comparison datetime.

    Returns:
        ``True`` when the expiry time is at or before the comparison time.

    Raises:
        ValueError: If either datetime is timezone-naive.
    """
    comparison_time = utc_now() if now is None else require_aware(now)

    return to_utc(expiry) <= to_utc(comparison_time)


def current_date_string() -> str:
    """Return the current date in the configured application timezone.

    Returns:
        ISO 8601 application-local date string.
    """
    return current_datetime().date().isoformat()


def current_time_string() -> str:
    """Return the current time in the configured application timezone.

    Returns:
        ISO 8601 application-local time string including its UTC offset.
    """
    return current_datetime().timetz().isoformat()


def start_of_application_day(
    value: datetime | None = None,
) -> datetime:
    """Return the start of a day in the configured application timezone.

    Args:
        value: Optional timezone-aware datetime. When omitted, the current
            application-local datetime is used.

    Returns:
        Application-local datetime set to midnight.

    Raises:
        ValueError: If ``value`` is timezone-naive.
    """
    local_value = (
        current_datetime()
        if value is None
        else to_application_timezone(value)
    )

    return local_value.replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )


def clear_timezone_cache() -> None:
    """Clear the cached application timezone.

    This function is intended for tests that override configuration or
    environment variables between test cases.
    """
    application_timezone.cache_clear()


__all__ = [
    "UTC",
    "application_timezone",
    "clear_timezone_cache",
    "current_date_string",
    "current_datetime",
    "current_time_string",
    "datetime_to_iso",
    "datetime_to_utc_iso",
    "is_expired",
    "parse_iso_datetime",
    "require_aware",
    "start_of_application_day",
    "to_application_timezone",
    "to_utc",
    "utc_now",
]