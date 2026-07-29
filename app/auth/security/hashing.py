"""Security primitives for authentication hashing operations."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid

from app.core.config import AppSettings


class SecureHashing:
    """Provide domain-separated HMAC hashing for authentication secrets."""

    def __init__(self, settings: AppSettings) -> None:
        self._pepper = settings.auth_pepper_value.encode("utf-8")

    def digest(self, value: str, *, namespace: str) -> str:
        """Create a domain-separated HMAC digest."""
        message = f"{namespace}:{value}".encode("utf-8")
        return hmac.new(self._pepper, message, hashlib.sha256).hexdigest()

    def token_hash(self, token: str) -> str:
        """Hash a refresh token before persistence."""
        return self.digest(token, namespace="refresh-token")

    def destination_hash(self, destination: str) -> str:
        """Hash an OTP destination before persistence."""
        return self.digest(destination, namespace="otp-destination")

    def otp_hash(self, challenge_id: uuid.UUID, otp: str) -> str:
        """Hash an OTP using its challenge identifier as context."""
        return self.digest(f"{challenge_id}:{otp}", namespace="otp-code")

    def verify_otp_hash(self, challenge_id: uuid.UUID, otp: str, expected: str) -> bool:
        """Compare an OTP against its stored hash in constant time."""
        return hmac.compare_digest(self.otp_hash(challenge_id, otp), expected)

    def identifier_hash(self, identifier: str) -> str:
        """Hash a login identifier for audit storage."""
        return self.digest(identifier, namespace="login-identifier")

    @staticmethod
    def generate_otp() -> str:
        """Generate a cryptographically secure six-digit OTP."""
        return f"{secrets.randbelow(1_000_000):06d}"


__all__ = ["SecureHashing"]
