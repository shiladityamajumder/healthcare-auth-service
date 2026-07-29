"""Security primitives for authentication passwords operations."""

from __future__ import annotations

import re

from anyio import to_thread
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

from app.common.exceptions import ValidationError
from app.core.config import AppSettings


class PasswordManager:
    """Argon2id password hashing with event-loop-safe execution."""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings
        self._hasher = PasswordHasher(
            time_cost=2,
            memory_cost=19_456,
            parallelism=1,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        # Precomputed with the same Argon2id policy to avoid blocking the first request.
        self._dummy_hash = (
            "$argon2id$v=19$m=19456,t=2,p=1$3yOnmNqL0zzxOnUaDlPomA$"
            "BX85wMWr29M1lQYNhYdKTrm76sq8d9xoARbVOwc6CgM"
        )

    def validate_strength(
        self,
        password: str,
        *,
        email: str | None = None,
        phone_number: str | None = None,
    ) -> None:
        """Enforce the configured password policy."""
        if len(password) < self._settings.PASSWORD_MIN_LENGTH:
            raise ValidationError(
                f"Password must contain at least {self._settings.PASSWORD_MIN_LENGTH} characters."
            )
        if len(password) > 128:
            raise ValidationError("Password must not exceed 128 characters.")
        if password.strip() != password:
            raise ValidationError("Password must not start or end with whitespace.")
        categories = sum(
            bool(pattern.search(password))
            for pattern in (
                re.compile(r"[a-z]"),
                re.compile(r"[A-Z]"),
                re.compile(r"[0-9]"),
                re.compile(r"[^A-Za-z0-9]"),
            )
        )
        if categories < 3:
            raise ValidationError(
                "Password must use at least three of uppercase, lowercase, number, and symbol."
            )
        lowered = password.casefold()
        if email:
            local_part = email.split("@", 1)[0].casefold()
            if len(local_part) >= 4 and local_part in lowered:
                raise ValidationError("Password must not contain the email username.")
        if phone_number and len(phone_number) >= 6 and phone_number[-6:] in password:
            raise ValidationError("Password must not contain the phone number.")

    async def hash(self, password: str) -> str:
        """Hash a password using the configured password hasher."""
        return await to_thread.run_sync(self._hasher.hash, password)

    async def verify(self, password_hash: str, password: str) -> bool:
        """Verify the submitted proof and complete the workflow."""
        return await to_thread.run_sync(self._verify_sync, password_hash, password)

    async def verify_dummy(self, password: str) -> None:
        """Perform a dummy password verification to reduce enumeration timing leaks."""
        await self.verify(self._dummy_hash, password)

    def needs_rehash(self, password_hash: str) -> bool:
        """Return whether a stored password hash needs upgrading."""
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True

    def _verify_sync(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


__all__ = ["PasswordManager"]
