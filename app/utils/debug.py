"""Development-only debug logging compatibility helper.

The original arbitrary ``print(*objects)`` utility could bypass redaction and
leak prescription, patient, credential, or token data. This replacement emits
through the central logging pipeline and accepts only a message plus explicitly
named structured context.
"""

from __future__ import annotations

from typing import Any

from app.core.config import Environment, get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def debug(message: str, **context: Any) -> None:
    """Emit a redacted debug event outside production.

    Args:
        message: Non-sensitive event description.
        **context: Structured context processed by the logging redactor.
    """
    settings = get_settings()
    if settings.ENVIRONMENT == Environment.PRODUCTION or not settings.DEBUG:
        return
    logger.debug(message, extra=context)


__all__ = ["debug"]
