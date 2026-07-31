"""File: app/modules/token_management/schemas.py

Purpose:
Defines refresh/logout inputs and public JWKS response contracts.

Dependency flow:
HTTP body or TokenManager JWKS output
-> strict Pydantic validation
-> token route/service
-> response-model serialization
"""

from __future__ import annotations

from pydantic import Field

from app.common.auth_contracts import MessageResponse, TokenPairResponse, UserResponse
from app.common.schemas import StrictModel


class RefreshTokenRequest(StrictModel):
    """Refresh token used to rotate its persisted session."""

    refresh_token: str = Field(min_length=32, max_length=8192)


class LogoutRequest(StrictModel):
    """Refresh token identifying the session to revoke."""

    refresh_token: str = Field(min_length=32, max_length=8192)


class JWKResponse(StrictModel):
    """Public JSON Web Key."""

    kty: str
    kid: str
    use: str
    alg: str
    n: str
    e: str


class JWKSResponse(StrictModel):
    """Current public JWT verification keys."""

    keys: list[JWKResponse]


__all__ = [
    "JWKResponse",
    "JWKSResponse",
    "LogoutRequest",
    "MessageResponse",
    "RefreshTokenRequest",
    "TokenPairResponse",
    "UserResponse",
]
