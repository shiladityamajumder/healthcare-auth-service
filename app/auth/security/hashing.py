"""File: app/auth/security/hashing.py

Purpose:
Provides domain-separated deterministic HMAC hashing for non-password
authentication values that require private, stable lookup keys.

Dependency flow:
Workflow-owned normalized value and namespace
-> SecureHashing
-> peppered HMAC digest
-> repository lookup or rate-limit backend key

This module provides domain-separated HMAC-SHA256 hashing for opaque
authentication tokens, OTP challenges, normalized destinations, audit
identifiers, and rate-limit dimensions.

The resulting digests are deterministic and suitable for indexed lookup. They
are not password hashes. User passwords must be processed exclusively through
``PasswordManager``.

The application authentication pepper is process-wide security material.
Rotating it invalidates persisted digests unless a versioned migration or
compatibility strategy is implemented.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from typing import Final

from app.core.config import AppSettings

# These values are domain-separation labels, not credentials or token values.
# Changing an existing label would invalidate persisted hashes.
_REFRESH_TOKEN_NAMESPACE: Final[str] = "refresh-token"  # noqa: S105
_OTP_DESTINATION_NAMESPACE: Final[str] = "otp-destination"
_OTP_CODE_NAMESPACE: Final[str] = "otp-code"
_LOGIN_IDENTIFIER_NAMESPACE: Final[str] = "login-identifier"

_OTP_UPPER_BOUND: Final[int] = 1_000_000
_MAX_NAMESPACE_LENGTH: Final[int] = 128


class SecureHashing:
    """Provide domain-separated HMAC hashing for authentication values."""

    def __init__(
        self,
        settings: AppSettings,
    ) -> None:
        """Initialize hashing with the configured authentication pepper.

        Args:
            settings: Validated immutable application settings.
        """
        self._pepper = settings.auth_pepper_value.encode()

    def digest(
        self,
        value: str,
        *,
        namespace: str,
    ) -> str:
        """Create a domain-separated HMAC-SHA256 digest.

        Values are deliberately not normalized here. Callers must normalize
        email, phone, client, device, and other identity values at their owning
        boundary before hashing.

        Args:
            value: Nonempty value to hash.
            namespace: Nonblank domain-separation namespace.

        Returns:
            Lowercase hexadecimal HMAC-SHA256 digest.

        Raises:
            ValueError: If the value is empty or the namespace is invalid.
        """
        if not value:
            raise ValueError(
                "Hashing value must not be empty."
            )

        normalized_namespace = namespace.strip()

        if not normalized_namespace:
            raise ValueError(
                "Hashing namespace must not be blank."
            )

        if len(normalized_namespace) > _MAX_NAMESPACE_LENGTH:
            raise ValueError(
                "Hashing namespace must not exceed "
                f"{_MAX_NAMESPACE_LENGTH} characters."
            )

        if any(
            ord(character) < 32 or ord(character) == 127
            for character in normalized_namespace
        ):
            raise ValueError(
                "Hashing namespace contains invalid control characters."
            )

        message = (
            f"{normalized_namespace}:{value}"
        ).encode()

        return hmac.new(
            self._pepper,
            message,
            hashlib.sha256,
        ).hexdigest()

    def token_hash(
        self,
        token: str,
    ) -> str:
        """Hash an opaque refresh or session token before persistence.

        Args:
            token: Raw opaque token.

        Returns:
            Deterministic token digest.

        Raises:
            ValueError: If the token is empty.
        """
        return self.digest(
            token,
            namespace=_REFRESH_TOKEN_NAMESPACE,
        )

    def destination_hash(
        self,
        destination: str,
    ) -> str:
        """Hash a canonical OTP destination before persistence.

        Args:
            destination: Canonical email or phone destination.

        Returns:
            Deterministic destination digest.

        Raises:
            ValueError: If the destination is empty.
        """
        return self.digest(
            destination,
            namespace=_OTP_DESTINATION_NAMESPACE,
        )

    def otp_hash(
        self,
        challenge_id: uuid.UUID,
        otp: str,
    ) -> str:
        """Hash an OTP using its challenge identifier as context.

        Binding the OTP to its challenge prevents an OTP digest from being
        reused across separate challenges.

        Args:
            challenge_id: OTP challenge identifier.
            otp: Raw OTP value.

        Returns:
            Deterministic challenge-bound OTP digest.

        Raises:
            ValueError: If the OTP value is empty.
        """
        if not otp:
            raise ValueError(
                "OTP value must not be empty."
            )

        return self.digest(
            f"{challenge_id}:{otp}",
            namespace=_OTP_CODE_NAMESPACE,
        )

    def verify_otp_hash(
        self,
        challenge_id: uuid.UUID,
        otp: str,
        expected: str,
    ) -> bool:
        """Compare an OTP against its stored digest in constant time.

        Args:
            challenge_id: OTP challenge identifier.
            otp: Submitted OTP value.
            expected: Stored OTP digest.

        Returns:
            ``True`` when the submitted OTP matches the stored digest.
        """
        if not otp or not expected:
            return False

        candidate = self.otp_hash(
            challenge_id,
            otp,
        )

        return hmac.compare_digest(
            candidate,
            expected,
        )

    def identifier_hash(
        self,
        identifier: str,
    ) -> str:
        """Hash a canonical login identifier for audit persistence.

        Args:
            identifier: Canonical email or phone identity.

        Returns:
            Deterministic identifier digest.

        Raises:
            ValueError: If the identifier is empty.
        """
        return self.digest(
            identifier,
            namespace=_LOGIN_IDENTIFIER_NAMESPACE,
        )

    @staticmethod
    def generate_otp() -> str:
        """Generate a cryptographically secure six-digit OTP.

        Returns:
            Zero-padded six-digit OTP.
        """
        return f"{secrets.randbelow(_OTP_UPPER_BOUND):06d}"


__all__ = [
    "SecureHashing",
]
