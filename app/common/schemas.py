"""File: app/common/schemas.py
Shared Pydantic primitives used by API modules.

Only transport-level base classes belong here. Endpoint request and response
contracts remain inside their owning vertical module.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    """Reject unknown fields and normalize surrounding string whitespace."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DeviceContext(StrictModel):
    """Optional device metadata accepted by session-creating workflows.

    These values are metadata only. They never replace JWT authentication or
    server-side session validation.
    """

    device_id: str | None = Field(default=None, max_length=255)
    device_type: str | None = Field(default=None, max_length=32)
    device_name: str | None = Field(default=None, max_length=128)
    device_fingerprint: str | None = Field(default=None, min_length=16, max_length=512)

    @field_validator("device_id", "device_type", "device_name", "device_fingerprint")
    @classmethod
    def blank_to_none(cls, value: str | None) -> str | None:
        """Convert whitespace-only device values to ``None``."""
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


__all__ = ["DeviceContext", "StrictModel"]
