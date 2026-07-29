"""Refresh-token rotation and logout contracts owned by this module."""

from __future__ import annotations

from pydantic import Field

from app.common.auth_contracts import MessageResponse, TokenPairResponse, UserResponse
from app.common.schemas import DeviceContext, StrictModel


class RefreshTokenRequest(DeviceContext):
    """Refresh token and optional updated device metadata."""

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
