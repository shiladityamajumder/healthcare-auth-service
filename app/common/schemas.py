"""File: app/common/schemas.py

Purpose:
Defines the strict shared Pydantic base used by transport schemas.

Dependency flow:
HTTP input or service output
-> StrictModel validation
-> owning module schema
-> route or service

Only transport-level base classes belong here. Endpoint request and response
contracts remain inside their owning vertical module.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Reject unknown fields and normalize surrounding string whitespace."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


__all__ = ["StrictModel"]
