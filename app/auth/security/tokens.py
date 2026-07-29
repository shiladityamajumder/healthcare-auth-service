"""Security primitives for authentication tokens operations."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt
from jwt import InvalidTokenError
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from app.common.exceptions import AuthenticationError
from app.core.config import AppSettings, JWTAlgorithm
from app.utils.datetime_utils import utc_now


class TokenType(StrEnum):
    """Supported signed token purposes for the public authentication API."""

    ACCESS = "access"
    REFRESH = "refresh"
    PASSWORD_RESET = "password_reset"


@dataclass(frozen=True, slots=True)
class EncodedToken:
    """Signed token value with expiry and unique token identifier."""

    token: str
    expires_at: datetime
    jti: uuid.UUID


class TokenManager:
    """Create and validate signed authentication tokens."""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings
        self._algorithm = settings.JWT_ALGORITHM.value
        if settings.JWT_ALGORITHM is JWTAlgorithm.HS256:
            self._encoding_key = settings.jwt_secret_value
        else:
            self._encoding_key = settings.jwt_private_key
        self._decoding_keys = settings.jwt_decoding_keys

    def create_access_token(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
        roles: list[str],
        permissions: list[str],
        auth_methods: list[str],
    ) -> EncodedToken:
        """Create a short-lived access token for one persisted session."""
        return self._encode(
            token_type=TokenType.ACCESS,
            subject=str(user_id),
            ttl=timedelta(minutes=self._settings.ACCESS_TOKEN_TTL_MINUTES),
            extra={
                "sid": str(session_id),
                "roles": roles,
                "permissions": permissions,
                "amr": auth_methods,
            },
        )

    def create_refresh_token(
        self,
        *,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
        family_id: uuid.UUID,
    ) -> EncodedToken:
        """Create a refresh token bound to one session and token family."""
        return self._encode(
            token_type=TokenType.REFRESH,
            subject=str(user_id),
            ttl=timedelta(days=self._settings.REFRESH_TOKEN_TTL_DAYS),
            extra={"sid": str(session_id), "fam": str(family_id)},
        )

    def create_password_reset_token(
        self,
        *,
        user_id: uuid.UUID,
        challenge_id: uuid.UUID,
        channel: str,
        destination_hash: str,
    ) -> EncodedToken:
        """Create a short-lived reset proof bound to one consumed OTP challenge."""
        return self._encode(
            token_type=TokenType.PASSWORD_RESET,
            subject=str(user_id),
            ttl=timedelta(
                minutes=self._settings.PASSWORD_RESET_TOKEN_TTL_MINUTES
            ),
            extra={
                "challenge_id": str(challenge_id),
                "channel": channel,
                "destination_hash": destination_hash,
            },
        )

    def decode(self, token: str, *, expected_type: TokenType) -> dict[str, Any]:
        """Validate a token and enforce its expected purpose."""
        try:
            header = jwt.get_unverified_header(token)
            key_id = str(header.get("kid", ""))
            decoding_key = self._decoding_keys.get(key_id)
            if decoding_key is None:
                raise InvalidTokenError("Unknown signing key")
            payload = jwt.decode(
                token,
                decoding_key,
                algorithms=[self._algorithm],
                audience=self._settings.JWT_AUDIENCE,
                issuer=self._settings.JWT_ISSUER,
                options={
                    "require": ["sub", "iat", "nbf", "exp", "iss", "aud", "jti", "token_type"],
                },
            )
        except InvalidTokenError as exc:
            raise AuthenticationError("The supplied token is invalid or expired.") from exc

        if payload.get("token_type") != expected_type.value:
            raise AuthenticationError("The supplied token type is not accepted here.")
        return payload

    def public_jwks(self) -> list[dict[str, str]]:
        """Return public RSA keys in JWKS form without exposing private material."""
        if self._settings.JWT_ALGORITHM is not JWTAlgorithm.RS256:
            return []
        keys: list[dict[str, str]] = []
        for key_id, public_key in self._decoding_keys.items():
            key_object = load_pem_public_key(public_key.encode("utf-8"))
            raw = json.loads(RSAAlgorithm.to_jwk(key_object))
            keys.append(
                {
                    "kty": str(raw["kty"]),
                    "kid": key_id,
                    "use": "sig",
                    "alg": self._algorithm,
                    "n": str(raw["n"]),
                    "e": str(raw["e"]),
                }
            )
        return keys

    def _encode(
        self,
        *,
        token_type: TokenType,
        subject: str,
        ttl: timedelta,
        extra: dict[str, Any],
    ) -> EncodedToken:
        now = utc_now()
        expires_at = now + ttl
        jti = uuid.uuid4()
        payload: dict[str, Any] = {
            "sub": subject,
            "token_type": token_type.value,
            "jti": str(jti),
            "iat": now,
            "nbf": now,
            "exp": expires_at,
            "iss": self._settings.JWT_ISSUER,
            "aud": self._settings.JWT_AUDIENCE,
            **extra,
        }
        token = jwt.encode(
            payload,
            self._encoding_key,
            algorithm=self._algorithm,
            headers={"kid": self._settings.JWT_KEY_ID, "typ": "JWT"},
        )
        return EncodedToken(token=token, expires_at=expires_at, jti=jti)


__all__ = ["EncodedToken", "TokenManager", "TokenType"]
