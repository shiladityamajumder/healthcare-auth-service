"""File: app/auth/request_context/context.py
Immutable authentication request metadata.

This module converts trusted connection information and validated authentication
headers into a request-scoped context consumed by authentication workflows.

Client-provided user and session identifiers remain consistency assertions.
They never authenticate a request independently of a signed token.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from typing import Self

from fastapi import Request

from app.auth.request_context.headers import AuthHeaders
from app.common.exceptions import ValidationError
from app.core.config import AppSettings
from app.core.request_context import (
    get_correlation_id,
    get_request_id,
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def request_uuid(value: str | None) -> uuid.UUID | None:
    """Parse an optional request identifier for UUID-backed audit columns."""
    if not value:
        return None

    try:
        return uuid.UUID(value)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class AuthRequestContext:
    """Immutable request metadata supplied to authentication workflows."""

    ip_address: str | None
    user_agent: str | None

    request_id: str | None
    correlation_id: str | None

    client_id: str | None
    client_version: str | None
    platform: str | None

    device_id: str | None
    device_type: str | None
    device_name: str | None

    asserted_user_id: uuid.UUID | None
    asserted_session_id: uuid.UUID | None

    idempotency_key: str | None

    @classmethod
    def from_request(
        cls,
        request: Request,
        *,
        settings: AppSettings,
        headers: AuthHeaders,
    ) -> Self:
        """Build an authentication context from one FastAPI request.

        Args:
            request: Active FastAPI request.
            settings: Validated process-wide settings.
            headers: Validated authentication metadata headers.

        Returns:
            Immutable request-scoped authentication context.

        Raises:
            ValidationError: If non-typed request headers such as User-Agent
                contain invalid values.
        """
        return cls(
            ip_address=cls._client_ip(
                request,
                settings=settings,
            ),
            user_agent=cls._read_optional_header(
                request,
                name="user-agent",
                max_length=512,
            ),
            request_id=get_request_id(
                request.headers.get("x-request-id")
            ),
            correlation_id=get_correlation_id(
                request.headers.get("x-correlation-id")
            ),
            client_id=headers.client_id,
            client_version=headers.client_version,
            platform=headers.platform,
            device_id=headers.device_id,
            device_type=headers.device_type,
            device_name=headers.device_name,
            asserted_user_id=headers.user_id,
            asserted_session_id=headers.session_id,
            idempotency_key=headers.idempotency_key,
        )

    @staticmethod
    def _read_optional_header(
        request: Request,
        *,
        name: str,
        max_length: int,
    ) -> str | None:
        """Read and validate one optional request header."""
        value = request.headers.get(name)

        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            return None

        if len(normalized) > max_length:
            raise ValidationError(
                f"{name} exceeds the maximum allowed length."
            )

        if any(
            ord(character) < 32 or ord(character) == 127
            for character in normalized
        ):
            raise ValidationError(
                f"{name} contains invalid control characters."
            )

        return normalized

    @classmethod
    def _client_ip(
        cls,
        request: Request,
        *,
        settings: AppSettings,
    ) -> str | None:
        """Resolve the client IP without trusting unverified proxy headers.

        ``X-Forwarded-For`` is considered only when the direct connection peer
        belongs to a configured trusted proxy network.

        The forwarded chain is evaluated from right to left. The first address
        that is not a trusted proxy is treated as the effective client.
        """
        direct_host = (
            request.client.host
            if request.client is not None
            else None
        )

        if direct_host is None:
            return None

        direct_host = direct_host.strip()

        if not direct_host:
            return None

        direct_address = cls._parse_ip(direct_host)

        # Preserve non-IP direct peer names in local test environments.
        if direct_address is None:
            return direct_host

        normalized_direct_ip = str(direct_address)

        if not settings.TRUSTED_PROXY_ENABLED:
            return normalized_direct_ip

        if not cls._is_trusted_proxy(
            direct_address,
            settings.TRUSTED_PROXY_CIDRS,
        ):
            return normalized_direct_ip

        forwarded_header = request.headers.get(
            "x-forwarded-for"
        )

        if not forwarded_header:
            return normalized_direct_ip

        forwarded_addresses = cls._parse_forwarded_chain(
            forwarded_header
        )

        if forwarded_addresses is None:
            return normalized_direct_ip

        for address in reversed(forwarded_addresses):
            if not cls._is_trusted_proxy(
                address,
                settings.TRUSTED_PROXY_CIDRS,
            ):
                return str(address)

        # Every address in the supplied chain belongs to a trusted proxy
        # network, so the chain cannot identify an untrusted client safely.
        return normalized_direct_ip

    @staticmethod
    def _parse_forwarded_chain(
        value: str,
    ) -> tuple[IPAddress, ...] | None:
        """Parse an X-Forwarded-For chain.

        A malformed chain is rejected as a whole rather than partially trusted.
        """
        raw_values = [
            item.strip()
            for item in value.split(",")
        ]

        if not raw_values or any(
            not item
            for item in raw_values
        ):
            return None

        parsed_addresses: list[IPAddress] = []

        for raw_value in raw_values:
            address = AuthRequestContext._parse_ip(
                raw_value
            )

            if address is None:
                return None

            parsed_addresses.append(address)

        return tuple(parsed_addresses)

    @staticmethod
    def _parse_ip(
        value: str,
    ) -> IPAddress | None:
        """Parse an IPv4 or IPv6 address without raising."""
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    @staticmethod
    def _is_trusted_proxy(
        address: IPAddress,
        cidrs: list[str],
    ) -> bool:
        """Return whether an address belongs to a trusted proxy network."""
        for cidr in cidrs:
            network = ipaddress.ip_network(
                cidr,
                strict=False,
            )

            if address.version != network.version:
                continue

            if address in network:
                return True

        return False


__all__ = [
    "AuthRequestContext",
    "request_uuid",
]
