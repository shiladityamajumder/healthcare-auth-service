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
from pydantic.alias_generators import to_camel


class StrictModel(BaseModel):
    """Keep Python names snake_case while exposing camelCase transport fields."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        populate_by_name=True,
        str_strip_whitespace=True,
    )


__all__ = ["StrictModel"]
