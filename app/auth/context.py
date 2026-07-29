"""Shared authentication context infrastructure."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from fastapi import Request

from app.common.exceptions import ValidationError
from app.core.config import AppSettings
from app.auth.headers import AuthHeaders
from app.core.request_context import get_correlation_id, get_request_id

_ALLOWED_PLATFORMS = {"web", "android", "ios", "service"}


@dataclass(frozen=True, slots=True)
class AuthRequestContext:
    """Immutable request metadata supplied to authentication workflows."""

    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    correlation_id: str | None = None
    client_id: str | None = None
    client_version: str | None = None
    platform: str | None = None
    device_id: str | None = None
    device_type: str | None = None
    device_name: str | None = None
    asserted_user_id: str | None = None
    asserted_session_id: str | None = None
    idempotency_key: str | None = None

    @classmethod
    def from_request(
        cls,
        request: Request,
        settings: AppSettings | None = None,
        headers: AuthHeaders | None = None,
    ) -> "AuthRequestContext":
        """Create request context from trusted server data and typed headers."""
        supplied = headers or AuthHeaders(
            client_id=cls._header(request, "x-client-id", 128),
            client_version=cls._header(request, "x-client-version", 64),
            platform=cls._header(request, "x-platform", 16),
            device_id=cls._header(request, "x-device-id", 255),
            device_type=cls._header(request, "x-device-type", 32),
            device_name=cls._header(request, "x-device-name", 128),
            idempotency_key=cls._header(request, "idempotency-key", 128),
        )
        platform = supplied.platform
        if platform is not None:
            platform = platform.casefold()
            if platform not in _ALLOWED_PLATFORMS:
                raise ValidationError(
                    "X-Platform must be one of web, android, ios, or service."
                )
        return cls(
            ip_address=cls._client_ip(request, settings),
            user_agent=cls._header(request, "user-agent", 512),
            request_id=get_request_id(request.headers.get("x-request-id")),
            correlation_id=get_correlation_id(
                request.headers.get("x-correlation-id")
            ),
            client_id=supplied.client_id,
            client_version=supplied.client_version,
            platform=platform,
            device_id=supplied.device_id,
            device_type=supplied.device_type,
            device_name=supplied.device_name,
            asserted_user_id=(str(supplied.user_id) if supplied.user_id else None),
            asserted_session_id=(
                str(supplied.session_id) if supplied.session_id else None
            ),
            idempotency_key=supplied.idempotency_key,
        )

    @staticmethod
    def _header(request: Request, name: str, max_length: int) -> str | None:
        value = request.headers.get(name)
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if len(normalized) > max_length:
            raise ValidationError(f"{name} exceeds the maximum allowed length.")
        if any(ord(character) < 32 for character in normalized):
            raise ValidationError(f"{name} contains invalid control characters.")
        return normalized

    @staticmethod
    def _client_ip(request: Request, settings: AppSettings | None) -> str | None:
        direct_ip = request.client.host if request.client else None
        if settings is None or not settings.TRUSTED_PROXY_ENABLED:
            return direct_ip
        if direct_ip is None or not AuthRequestContext._ip_in_trusted_proxy(
            direct_ip,
            settings.TRUSTED_PROXY_CIDRS,
        ):
            return direct_ip
        forwarded = request.headers.get("x-forwarded-for")
        if not forwarded:
            return direct_ip
        first = forwarded.split(",", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(first))
        except ValueError:
            return direct_ip

    @staticmethod
    def _ip_in_trusted_proxy(ip_value: str, cidrs: list[str]) -> bool:
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError:
            return False
        for cidr in cidrs:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False


__all__ = ["AuthRequestContext"]
