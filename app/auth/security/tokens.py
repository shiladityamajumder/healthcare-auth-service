"""File: app/auth/security/tokens.py

Purpose:
Creates and verifies signed access, refresh, and password-reset JWTs and
publishes configured RSA public keys as JWKS.

Dependency flow:
Validated settings and workflow claims
-> TokenManager encode/decode
-> fixed algorithm/key registry and claim checks
-> token string or verified claim mapping
-> session/workflow dependency

This module creates and verifies JWT access, refresh, and password-reset
tokens. It also publishes configured RSA verification keys in JWKS-compatible
form.

Token verification uses a fixed configured algorithm allow-list and selects
verification keys only from the application's validated key registry. JWT
headers are never treated as trusted until signature verification succeeds.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Final

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from jwt import InvalidTokenError
from jwt.algorithms import RSAAlgorithm

from app.common.exceptions import AuthenticationError
from app.core.config import AppSettings, JWTAlgorithm
from app.utils.datetime_utils import utc_now


class TokenType(StrEnum):
    """Supported signed-token purposes."""

    ACCESS = "access"
    REFRESH = "refresh"
    PASSWORD_RESET = "password_reset"  # noqa: S105


@dataclass(frozen=True, slots=True)
class EncodedToken:
    """Signed token value and associated metadata."""

    token: str
    expires_at: datetime
    jti: uuid.UUID


_REGISTERED_CLAIMS: Final[frozenset[str]] = frozenset(
    {
        "sub",
        "token_type",
        "jti",
        "iat",
        "nbf",
        "exp",
        "iss",
        "aud",
    }
)

_BASE_REQUIRED_CLAIMS: Final[tuple[str, ...]] = (
    "sub",
    "token_type",
    "jti",
    "iat",
    "nbf",
    "exp",
    "iss",
    "aud",
)

_TOKEN_REQUIRED_CLAIMS: Final[
    dict[TokenType, frozenset[str]]
] = {
    TokenType.ACCESS: frozenset(
        {
            "sid",
            "roles",
            "permissions",
            "amr",
        }
    ),
    TokenType.REFRESH: frozenset(
        {
            "sid",
            "fam",
        }
    ),
    TokenType.PASSWORD_RESET: frozenset(
        {
            "challenge_id",
            "channel",
            "destination_hash",
        }
    ),
}

_JWT_HEADER_TYPE: Final[str] = "JWT"


class TokenManager:
    """Create, validate, and publish authentication tokens."""

    def __init__(
        self,
        settings: AppSettings,
    ) -> None:
        """Initialize token signing and verification material.

        Args:
            settings: Validated immutable application settings.

        Raises:
            RuntimeError: If signing or decoding key material is missing.
        """
        self._settings = settings
        self._algorithm = settings.JWT_ALGORITHM.value

        encoding_key = (
            settings.jwt_secret_value
            if settings.JWT_ALGORITHM is JWTAlgorithm.HS256
            else settings.jwt_private_key
        )

        if not encoding_key:
            raise RuntimeError(
                "JWT encoding key is not configured."
            )

        decoding_keys = settings.jwt_decoding_keys

        if not decoding_keys:
            raise RuntimeError(
                "JWT decoding keys are not configured."
            )

        if settings.JWT_KEY_ID not in decoding_keys:
            raise RuntimeError(
                "The current JWT key identifier is missing from the "
                "decoding-key registry."
            )

        self._encoding_key: str = encoding_key
        self._decoding_keys: dict[str, str] = dict(
            decoding_keys
        )
        self._public_jwk_entries = self._build_public_jwks()

    def create_access_token(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
        roles: Sequence[str],
        permissions: Sequence[str],
        auth_methods: Sequence[str],
    ) -> EncodedToken:
        """Create a short-lived access token for one session.

        Args:
            user_id: Authenticated user identifier.
            session_id: Persisted session identifier.
            roles: Effective global role codes.
            permissions: Effective global permission codes.
            auth_methods: Authentication method references.

        Returns:
            Signed access token.
        """
        return self._encode(
            token_type=TokenType.ACCESS,
            subject=str(user_id),
            ttl=timedelta(
                minutes=self._settings.ACCESS_TOKEN_TTL_MINUTES
            ),
            extra={
                "sid": str(session_id),
                "roles": self._normalize_string_claims(
                    roles,
                    claim_name="roles",
                ),
                "permissions": self._normalize_string_claims(
                    permissions,
                    claim_name="permissions",
                ),
                "amr": self._normalize_string_claims(
                    auth_methods,
                    claim_name="amr",
                ),
            },
        )

    def create_refresh_token(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
        family_id: uuid.UUID,
    ) -> EncodedToken:
        """Create a refresh token bound to a session and family.

        Args:
            user_id: Authenticated user identifier.
            session_id: Persisted session identifier.
            family_id: Refresh-token rotation family identifier.

        Returns:
            Signed refresh token.
        """
        return self._encode(
            token_type=TokenType.REFRESH,
            subject=str(user_id),
            ttl=timedelta(
                days=self._settings.REFRESH_TOKEN_TTL_DAYS
            ),
            extra={
                "sid": str(session_id),
                "fam": str(family_id),
            },
        )

    def create_password_reset_token(
        self,
        *,
        user_id: uuid.UUID,
        challenge_id: uuid.UUID,
        channel: str,
        destination_hash: str,
    ) -> EncodedToken:
        """Create a reset proof bound to a consumed OTP challenge.

        Args:
            user_id: User whose password may be reset.
            challenge_id: Consumed OTP challenge identifier.
            channel: Verified OTP channel.
            destination_hash: Hash of the verified destination.

        Returns:
            Signed password-reset token.

        Raises:
            ValueError: If the channel or destination hash is blank.
        """
        normalized_channel = channel.strip()
        normalized_destination_hash = destination_hash.strip()

        if not normalized_channel:
            raise ValueError(
                "Password-reset token channel must not be blank."
            )

        if not normalized_destination_hash:
            raise ValueError(
                "Password-reset destination hash must not be blank."
            )

        return self._encode(
            token_type=TokenType.PASSWORD_RESET,
            subject=str(user_id),
            ttl=timedelta(
                minutes=(
                    self._settings
                    .PASSWORD_RESET_TOKEN_TTL_MINUTES
                )
            ),
            extra={
                "challenge_id": str(challenge_id),
                "channel": normalized_channel,
                "destination_hash": normalized_destination_hash,
            },
        )

    def decode(
        self,
        token: str,
        *,
        expected_type: TokenType,
    ) -> dict[str, Any]:
        """Verify a signed token and enforce its expected purpose.

        Args:
            token: Signed compact JWT.
            expected_type: Token purpose accepted by the caller.

        Returns:
            Verified and structurally validated claims.

        Raises:
            AuthenticationError: If the token, signature, header, registered
                claims, purpose, or token-specific claims are invalid.
        """
        if not token or not token.strip():
            raise AuthenticationError(
                "The supplied token is invalid or expired."
            )

        try:
            header = jwt.get_unverified_header(token)

            key_id = self._validate_unverified_header(
                header
            )

            decoding_key = self._decoding_keys.get(
                key_id
            )

            if decoding_key is None:
                raise InvalidTokenError(
                    "Unknown JWT signing key."
                )

            payload = jwt.decode(
                token,
                decoding_key,
                algorithms=[
                    self._algorithm,
                ],
                audience=self._settings.JWT_AUDIENCE,
                issuer=self._settings.JWT_ISSUER,
                options={
                    "require": list(
                        _BASE_REQUIRED_CLAIMS
                    ),
                },
            )
        except InvalidTokenError as exc:
            raise AuthenticationError(
                "The supplied token is invalid or expired."
            ) from exc

        self._validate_payload_contract(
            payload,
            expected_type=expected_type,
        )

        return payload

    def public_jwks(
        self,
    ) -> list[dict[str, str]]:
        """Return configured RSA public keys in JWKS form.

        HS256 deployments return an empty collection because symmetric signing
        secrets must never be published.

        Returns:
            Copies of configured public JWK entries.
        """
        return [
            dict(entry)
            for entry in self._public_jwk_entries
        ]

    def _encode(
        self,
        *,
        token_type: TokenType,
        subject: str,
        ttl: timedelta,
        extra: dict[str, Any],
    ) -> EncodedToken:
        """Create one signed token with registered claims.

        Args:
            token_type: Purpose of the signed token.
            subject: JWT subject identifier.
            ttl: Token lifetime.
            extra: Purpose-specific claims.

        Returns:
            Signed token and associated metadata.

        Raises:
            ValueError: If the subject, lifetime, or extra claims are invalid.
        """
        normalized_subject = subject.strip()

        if not normalized_subject:
            raise ValueError(
                "JWT subject must not be blank."
            )

        if ttl <= timedelta(0):
            raise ValueError(
                "JWT lifetime must be greater than zero."
            )

        conflicting_claims = _REGISTERED_CLAIMS.intersection(
            extra
        )

        if conflicting_claims:
            conflicting_names = ", ".join(
                sorted(conflicting_claims)
            )

            raise ValueError(
                "Token-specific claims must not override registered claims: "
                f"{conflicting_names}"
            )

        now = utc_now()
        expires_at = now + ttl
        jti = uuid.uuid4()

        payload: dict[str, Any] = {
            "sub": normalized_subject,
            "token_type": token_type.value,
            "jti": str(jti),
            "iat": now,
            "nbf": now,
            "exp": expires_at,
            "iss": self._settings.JWT_ISSUER,
            "aud": self._settings.JWT_AUDIENCE,
        }
        payload.update(extra)

        encoded_value = jwt.encode(
            payload,
            self._encoding_key,
            algorithm=self._algorithm,
            headers={
                "kid": self._settings.JWT_KEY_ID,
                "typ": _JWT_HEADER_TYPE,
            },
        )

        return EncodedToken(
            token=encoded_value,
            expires_at=expires_at,
            jti=jti,
        )

    def _validate_unverified_header(
        self,
        header: Mapping[str, object],
    ) -> str:
        """Validate unverified routing fields before key selection.

        Only routing information is read before verification. The selected key
        remains restricted to the application's configured key registry.

        Args:
            header: Decoded but unverified JWT header.

        Returns:
            Validated signing-key identifier.

        Raises:
            InvalidTokenError: If the header algorithm, type, or key identifier
                is invalid.
        """
        header_algorithm = header.get("alg")

        if header_algorithm != self._algorithm:
            raise InvalidTokenError(
                "Unexpected JWT signing algorithm."
            )

        header_type = header.get("typ")

        if (
            header_type is not None
            and header_type != _JWT_HEADER_TYPE
        ):
            raise InvalidTokenError(
                "Unexpected JWT type header."
            )

        key_id = header.get("kid")

        if not isinstance(key_id, str):
            raise InvalidTokenError(
                "JWT signing-key identifier is missing."
            )

        normalized_key_id = key_id.strip()

        if not normalized_key_id:
            raise InvalidTokenError(
                "JWT signing-key identifier is missing."
            )

        return normalized_key_id

    def _validate_payload_contract(
        self,
        payload: Mapping[str, Any],
        *,
        expected_type: TokenType,
    ) -> None:
        """Validate token-purpose-specific claim structure.

        Args:
            payload: Verified JWT claims.
            expected_type: Token purpose accepted by the caller.

        Raises:
            AuthenticationError: If any required claim is missing or malformed.
        """
        if payload.get("token_type") != expected_type.value:
            raise AuthenticationError(
                "The supplied token type is not accepted here."
            )

        required_claims = _TOKEN_REQUIRED_CLAIMS[
            expected_type
        ]

        missing_claims = sorted(
            claim_name
            for claim_name in required_claims
            if claim_name not in payload
        )

        if missing_claims:
            raise AuthenticationError(
                "The supplied token contains incomplete claims."
            )

        self._require_uuid_claim(
            payload,
            claim_name="sub",
        )
        self._require_uuid_claim(
            payload,
            claim_name="jti",
        )

        if expected_type is TokenType.ACCESS:
            self._validate_access_claims(
                payload
            )
            return

        if expected_type is TokenType.REFRESH:
            self._validate_refresh_claims(
                payload
            )
            return

        self._validate_password_reset_claims(
            payload
        )

    def _validate_access_claims(
        self,
        payload: Mapping[str, Any],
    ) -> None:
        """Validate access-token-specific claims."""
        self._require_uuid_claim(
            payload,
            claim_name="sid",
        )
        self._require_string_collection(
            payload,
            claim_name="roles",
        )
        self._require_string_collection(
            payload,
            claim_name="permissions",
        )
        self._require_string_collection(
            payload,
            claim_name="amr",
        )

    def _validate_refresh_claims(
        self,
        payload: Mapping[str, Any],
    ) -> None:
        """Validate refresh-token-specific claims."""
        self._require_uuid_claim(
            payload,
            claim_name="sid",
        )
        self._require_uuid_claim(
            payload,
            claim_name="fam",
        )

    def _validate_password_reset_claims(
        self,
        payload: Mapping[str, Any],
    ) -> None:
        """Validate password-reset-token-specific claims."""
        self._require_uuid_claim(
            payload,
            claim_name="challenge_id",
        )
        self._require_nonblank_string_claim(
            payload,
            claim_name="channel",
        )
        self._require_nonblank_string_claim(
            payload,
            claim_name="destination_hash",
        )

    def _build_public_jwks(
        self,
    ) -> tuple[dict[str, str], ...]:
        """Build stable public JWK entries during initialization.

        Returns:
            Immutable public JWK entries.

        Raises:
            RuntimeError: If configured RSA public keys cannot be loaded or
                converted into valid JWK entries.
        """
        if (
            self._settings.JWT_ALGORITHM
            is not JWTAlgorithm.RS256
        ):
            return ()

        keys: list[dict[str, str]] = []

        for key_id in sorted(self._decoding_keys):
            public_key_pem = self._decoding_keys[
                key_id
            ]

            try:
                key_object = load_pem_public_key(
                    public_key_pem.encode()
                )
            except (
                TypeError,
                ValueError,
                UnsupportedAlgorithm,
            ) as exc:
                raise RuntimeError(
                    f"JWT public key {key_id!r} cannot be loaded."
                ) from exc

            if not isinstance(
                key_object,
                rsa.RSAPublicKey,
            ):
                raise RuntimeError(
                    f"JWT public key {key_id!r} is not an RSA key."
                )

            try:
                raw_jwk = json.loads(
                    RSAAlgorithm.to_jwk(
                        key_object
                    )
                )
            except (
                TypeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                raise RuntimeError(
                    f"JWT public key {key_id!r} produced invalid JWK data."
                ) from exc

            if not isinstance(raw_jwk, dict):
                raise RuntimeError(
                    f"JWT public key {key_id!r} produced invalid JWK data."
                )

            modulus = raw_jwk.get("n")
            exponent = raw_jwk.get("e")

            if (
                not isinstance(modulus, str)
                or not modulus
                or not isinstance(exponent, str)
                or not exponent
            ):
                raise RuntimeError(
                    f"JWT public key {key_id!r} produced incomplete JWK data."
                )

            keys.append(
                {
                    "kty": "RSA",
                    "kid": key_id,
                    "use": "sig",
                    "alg": self._algorithm,
                    "n": modulus,
                    "e": exponent,
                }
            )

        return tuple(keys)

    @staticmethod
    def _normalize_string_claims(
        values: Sequence[str],
        *,
        claim_name: str,
    ) -> list[str]:
        """Normalize and deduplicate outgoing collection claims.

        Args:
            values: Collection values supplied by the token issuer.
            claim_name: Claim name used in validation errors.

        Returns:
            Ordered, deduplicated string values.

        Raises:
            ValueError: If the input is a scalar string or contains invalid
                values.
        """
        if isinstance(values, (str, bytes)):
            raise ValueError(
                f"{claim_name} must be a collection of strings."
            )

        normalized: list[str] = []
        seen: set[str] = set()

        for value in values:
            if not isinstance(value, str):
                raise ValueError(
                    f"{claim_name} must contain only strings."
                )

            item = value.strip()

            if not item:
                raise ValueError(
                    f"{claim_name} must not contain blank values."
                )

            if item in seen:
                continue

            seen.add(item)
            normalized.append(item)

        return normalized

    @staticmethod
    def _require_uuid_claim(
        payload: Mapping[str, Any],
        *,
        claim_name: str,
    ) -> uuid.UUID:
        """Require one UUID-formatted claim.

        Args:
            payload: Verified JWT claims.
            claim_name: Required UUID claim name.

        Returns:
            Parsed UUID claim.

        Raises:
            AuthenticationError: If the claim is missing or malformed.
        """
        raw_value = payload.get(
            claim_name
        )

        if not isinstance(raw_value, str):
            raise AuthenticationError(
                "The supplied token contains invalid claims."
            )

        try:
            return uuid.UUID(
                raw_value
            )
        except ValueError as exc:
            raise AuthenticationError(
                "The supplied token contains invalid claims."
            ) from exc

    @staticmethod
    def _require_nonblank_string_claim(
        payload: Mapping[str, Any],
        *,
        claim_name: str,
    ) -> str:
        """Require one nonblank string claim.

        Args:
            payload: Verified JWT claims.
            claim_name: Required string claim name.

        Returns:
            Trimmed claim value.

        Raises:
            AuthenticationError: If the claim is missing, non-string, or blank.
        """
        raw_value = payload.get(
            claim_name
        )

        if not isinstance(raw_value, str):
            raise AuthenticationError(
                "The supplied token contains invalid claims."
            )

        normalized = raw_value.strip()

        if not normalized:
            raise AuthenticationError(
                "The supplied token contains invalid claims."
            )

        return normalized

    @staticmethod
    def _require_string_collection(
        payload: Mapping[str, Any],
        *,
        claim_name: str,
    ) -> tuple[str, ...]:
        """Require a JWT array containing nonblank strings.

        Args:
            payload: Verified JWT claims.
            claim_name: Required array claim name.

        Returns:
            Normalized claim values.

        Raises:
            AuthenticationError: If the claim is missing, not an array, or
                contains invalid values.
        """
        raw_value = payload.get(
            claim_name
        )

        if not isinstance(raw_value, list):
            raise AuthenticationError(
                "The supplied token contains invalid claims."
            )

        values: list[str] = []

        for item in raw_value:
            if not isinstance(item, str):
                raise AuthenticationError(
                    "The supplied token contains invalid claims."
                )

            normalized = item.strip()

            if not normalized:
                raise AuthenticationError(
                    "The supplied token contains invalid claims."
                )

            values.append(
                normalized
            )

        return tuple(
            values
        )


__all__ = [
    "EncodedToken",
    "TokenManager",
    "TokenType",
]
