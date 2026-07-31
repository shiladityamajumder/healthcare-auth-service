"""File: app/auth/security/passwords.py

Purpose:
Validates password policy and performs Argon2id hash, verification, and rehash
checks without blocking the async event loop.

Dependency flow:
Service-supplied password value
-> PasswordManager policy validation
-> worker-thread Argon2id operation
-> hash/verification result
-> service transaction decision

Password hashing and verification are CPU- and memory-intensive operations.
They are executed in worker threads so the application's asynchronous event
loop is not blocked.

The configured Argon2id parameters must be benchmarked in the actual deployment
environment. Changing those parameters does not invalidate existing hashes.
``needs_rehash`` identifies hashes that should be upgraded after successful
authentication.
"""

from __future__ import annotations

import re
from typing import Final

from anyio import to_thread
from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
)
from argon2.low_level import Type

from app.common.exceptions import ValidationError
from app.core.config import AppSettings

_LOWERCASE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z]")
_UPPERCASE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Z]")
_DIGIT_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9]")
_SYMBOL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]")
_NON_DIGIT_PATTERN: Final[re.Pattern[str]] = re.compile(r"\D+")

_PASSWORD_CATEGORY_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    _LOWERCASE_PATTERN,
    _UPPERCASE_PATTERN,
    _DIGIT_PATTERN,
    _SYMBOL_PATTERN,
)

_MAX_PASSWORD_LENGTH: Final[int] = 128
_MIN_IDENTITY_FRAGMENT_LENGTH: Final[int] = 4
_PHONE_COMPARISON_SUFFIX_LENGTH: Final[int] = 6

_ARGON2_TIME_COST: Final[int] = 2
_ARGON2_MEMORY_COST_KIB: Final[int] = 19_456
_ARGON2_PARALLELISM: Final[int] = 1
_ARGON2_HASH_LENGTH: Final[int] = 32
_ARGON2_SALT_LENGTH: Final[int] = 16

# This encoded Argon2 digest is intentionally embedded and is not a credential.
# It ensures unknown-account login attempts perform comparable verification
# work, reducing username-enumeration timing differences.
_DUMMY_ARGON2_DIGEST: Final[str] = (
    "$argon2id$v=19$m=19456,t=2,p=1$"
    "3yOnmNqL0zzxOnUaDlPomA$"
    "BX85wMWr29M1lQYNhYdKTrm76sq8d9xoARbVOwc6CgM"
)


class PasswordManager:
    """Provide password-policy enforcement and Argon2id processing."""

    def __init__(
        self,
        settings: AppSettings,
    ) -> None:
        """Initialize password policy and Argon2id parameters.

        Args:
            settings: Validated immutable application settings.
        """
        self._settings = settings

        self._hasher = PasswordHasher(
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST_KIB,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_ARGON2_HASH_LENGTH,
            salt_len=_ARGON2_SALT_LENGTH,
            type=Type.ID,
        )

    def validate_strength(
        self,
        password: str,
        *,
        email: str | None = None,
        phone_number: str | None = None,
    ) -> None:
        """Enforce the configured password policy.

        Email and phone values supplied to this method should already be
        normalized by the identity layer.

        Args:
            password: Candidate plaintext password.
            email: Optional normalized email identity.
            phone_number: Optional normalized national phone number.

        Raises:
            ValidationError: If the password violates the configured policy.
        """
        self._validate_length(password)
        self._validate_whitespace(password)
        self._validate_control_characters(password)
        self._validate_character_categories(password)
        self._validate_identity_fragments(
            password,
            email=email,
            phone_number=phone_number,
        )

    async def hash(
        self,
        password: str,
    ) -> str:
        """Hash a plaintext password using Argon2id.

        Password-strength validation is intentionally not performed here.
        Callers must invoke ``validate_strength`` before hashing passwords
        accepted from registration, reset, or change-password workflows.

        Args:
            password: Plaintext password.

        Returns:
            Encoded Argon2id password hash.

        Raises:
            ValueError: If the password is empty.
        """
        if not password:
            raise ValueError("Password must not be empty.")

        return await to_thread.run_sync(
            self._hasher.hash,
            password,
        )

    async def verify(
        self,
        password_hash: str,
        password: str,
    ) -> bool:
        """Verify a plaintext password against an encoded Argon2 hash.

        Malformed hashes and password mismatches both return ``False`` so
        authentication workflows do not expose different failure outcomes.

        Args:
            password_hash: Encoded Argon2 password hash.
            password: Submitted plaintext password.

        Returns:
            ``True`` when the password matches the stored hash.
        """
        if not password_hash:
            return False

        return await to_thread.run_sync(
            self._verify_sync,
            password_hash,
            password,
        )

    async def verify_dummy(
        self,
        password: str,
    ) -> None:
        """Perform dummy verification for unknown-account login attempts.

        The verification result is intentionally discarded. This reduces timing
        differences between login attempts for known and unknown accounts.

        Args:
            password: Submitted plaintext password.
        """
        await to_thread.run_sync(
            self._verify_sync,
            _DUMMY_ARGON2_DIGEST,
            password,
        )

    def needs_rehash(
        self,
        password_hash: str,
    ) -> bool:
        """Return whether a stored password hash needs upgrading.

        Args:
            password_hash: Encoded Argon2 password hash.

        Returns:
            ``True`` when the hash is malformed or uses outdated parameters.
        """
        if not password_hash:
            return True

        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True

    def _validate_length(
        self,
        password: str,
    ) -> None:
        """Validate minimum and maximum password length."""
        minimum_length = self._settings.PASSWORD_MIN_LENGTH

        if len(password) < minimum_length:
            raise ValidationError(f"Password must contain at least {minimum_length} characters.")

        if len(password) > _MAX_PASSWORD_LENGTH:
            raise ValidationError(f"Password must not exceed {_MAX_PASSWORD_LENGTH} characters.")

    @staticmethod
    def _validate_whitespace(
        password: str,
    ) -> None:
        """Reject leading or trailing password whitespace."""
        if password.strip() != password:
            raise ValidationError("Password must not start or end with whitespace.")

    @staticmethod
    def _validate_control_characters(
        password: str,
    ) -> None:
        """Reject null characters from passwords."""
        if "\x00" in password:
            raise ValidationError("Password contains an invalid null character.")

    @staticmethod
    def _validate_character_categories(
        password: str,
    ) -> None:
        """Require at least three supported character categories."""
        category_count = sum(
            bool(pattern.search(password)) for pattern in _PASSWORD_CATEGORY_PATTERNS
        )

        if category_count < 3:
            raise ValidationError(
                "Password must use at least three of uppercase, lowercase, number, and symbol."
            )

    @staticmethod
    def _validate_identity_fragments(
        password: str,
        *,
        email: str | None,
        phone_number: str | None,
    ) -> None:
        """Reject passwords containing meaningful identity fragments."""
        normalized_password = password.casefold()

        if email:
            local_part = email.split("@", 1)[0].strip().casefold()

            if (
                len(local_part) >= _MIN_IDENTITY_FRAGMENT_LENGTH
                and local_part in normalized_password
            ):
                raise ValidationError("Password must not contain the email username.")

        if phone_number:
            normalized_phone = _NON_DIGIT_PATTERN.sub(
                "",
                phone_number,
            )

            if len(normalized_phone) >= _PHONE_COMPARISON_SUFFIX_LENGTH:
                phone_suffix = normalized_phone[-_PHONE_COMPARISON_SUFFIX_LENGTH:]

                if phone_suffix in password:
                    raise ValidationError("Password must not contain the phone number.")

    def _verify_sync(
        self,
        password_hash: str,
        password: str,
    ) -> bool:
        """Execute synchronous Argon2 verification in a worker thread."""
        try:
            return bool(
                self._hasher.verify(
                    password_hash,
                    password,
                )
            )
        except (
            VerificationError,
            InvalidHashError,
        ):
            return False


__all__ = [
    "PasswordManager",
]
