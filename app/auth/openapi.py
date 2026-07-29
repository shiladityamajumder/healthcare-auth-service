"""Shared authentication openapi infrastructure."""

from __future__ import annotations

from app.common.response import APIResponseModel

AUTH_ERROR_RESPONSES: dict[int, dict[str, object]] = {
    400: {
        "model": APIResponseModel[None],
        "description": "Malformed or unsupported request.",
    },
    401: {
        "model": APIResponseModel[None],
        "description": "Credentials, token, OTP, or reset proof is invalid.",
    },
    403: {
        "model": APIResponseModel[None],
        "description": "The authenticated principal lacks authorization.",
    },
    404: {
        "model": APIResponseModel[None],
        "description": "The requested user-owned or administrative resource was not found.",
    },
    409: {
        "model": APIResponseModel[None],
        "description": "The operation conflicts with current persisted state.",
    },
    422: {
        "model": APIResponseModel[None],
        "description": "Request validation or password-policy failure.",
    },
    429: {
        "model": APIResponseModel[None],
        "description": "Rate limit, OTP cooldown, or attempt limit exceeded.",
    },
    500: {
        "model": APIResponseModel[None],
        "description": "Unexpected internal failure with no implementation details exposed.",
    },
    503: {
        "model": APIResponseModel[None],
        "description": "Required persistence or infrastructure is unavailable.",
    },
    504: {
        "model": APIResponseModel[None],
        "description": "A bounded operation exceeded its configured deadline.",
    },
}


__all__ = ["AUTH_ERROR_RESPONSES"]
