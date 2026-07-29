"""File: `app/core/execution.py`
    Execution primitives for observable, bounded asynchronous operations.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from app.common.exceptions import OperationTimeoutError
from app.core.logging import get_logger, sanitize_log_value

logger = get_logger(__name__)


async def execute_operation[T](
    *,
    operation: str,
    func: Callable[[], Awaitable[T]],
    layer: str = "application",
    timeout_seconds: float | None = None,
    context: Mapping[str, Any] | None = None,
) -> T:
    """Execute an asynchronous operation with centralized structured logging.

    The operation is logged at the following points:

    - DEBUG when execution starts
    - DEBUG when execution completes successfully
    - WARNING when execution exceeds its timeout
    - ERROR when execution raises an unexpected exception

    Request, correlation, and trace identifiers are attached automatically by
    the logging context filter.

    Args:
        operation: Stable human-readable operation name.
        func: Zero-argument asynchronous callable to execute.
        layer: Logical application layer, such as ``service`` or ``repository``.
        timeout_seconds: Optional maximum execution time in seconds.
        context: Optional non-sensitive structured metadata.

    Returns:
        Result returned by the asynchronous callable.

    Raises:
        ValueError: If operation or layer is blank, or timeout is invalid.
        OperationTimeoutError: If execution exceeds the configured timeout.
        Exception: Any non-timeout exception raised by ``func``.
    """
    normalized_operation = operation.strip()
    normalized_layer = layer.strip()

    if not normalized_operation:
        raise ValueError("operation must not be blank")

    if not normalized_layer:
        raise ValueError("layer must not be blank")

    if timeout_seconds is not None and timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    safe_context = sanitize_log_value(dict(context or {}))
    started = time.perf_counter()

    logger.debug(
        "Operation started",
        extra={
            "operation": normalized_operation,
            "layer": normalized_layer,
            "operation_context": safe_context,
            "timeout_seconds": timeout_seconds,
        },
    )

    try:
        if timeout_seconds is None:
            result = await func()
        else:
            async with asyncio.timeout(timeout_seconds):
                result = await func()

    except TimeoutError as exc:
        duration_ms = _elapsed_milliseconds(started)

        logger.warning(
            "Operation timed out",
            extra={
                "operation": normalized_operation,
                "layer": normalized_layer,
                "operation_context": safe_context,
                "duration_ms": duration_ms,
                "timeout_seconds": timeout_seconds,
                "exception_type": type(exc).__name__,
            },
        )

        raise OperationTimeoutError(
            f"{normalized_operation} exceeded its allowed execution time."
        ) from exc

    except Exception as exc:
        duration_ms = _elapsed_milliseconds(started)

        logger.exception(
            "Operation failed",
            extra={
                "operation": normalized_operation,
                "layer": normalized_layer,
                "operation_context": safe_context,
                "duration_ms": duration_ms,
                "exception_type": type(exc).__name__,
            },
        )

        raise

    duration_ms = _elapsed_milliseconds(started)

    logger.debug(
        "Operation completed",
        extra={
            "operation": normalized_operation,
            "layer": normalized_layer,
            "operation_context": safe_context,
            "duration_ms": duration_ms,
        },
    )

    return result


async def execute_with_timeout[T](
    *,
    operation: str,
    timeout_seconds: float,
    func: Callable[[], Awaitable[T]],
    layer: str = "application",
    context: Mapping[str, Any] | None = None,
) -> T:
    """Execute an asynchronous operation within an explicit deadline.

    This compatibility helper delegates to :func:`execute_operation` while
    retaining the explicit timeout-oriented interface.

    Args:
        operation: Stable human-readable operation name.
        timeout_seconds: Maximum execution time in seconds.
        func: Zero-argument asynchronous callable to execute.
        layer: Logical application layer.
        context: Optional non-sensitive structured metadata.

    Returns:
        Result returned by the asynchronous callable.

    Raises:
        ValueError: If operation, layer, or timeout is invalid.
        OperationTimeoutError: If execution exceeds the configured timeout.
        Exception: Any non-timeout exception raised by ``func``.
    """
    return await execute_operation(
        operation=operation,
        func=func,
        layer=layer,
        timeout_seconds=timeout_seconds,
        context=context,
    )


def _elapsed_milliseconds(started: float) -> float:
    """Return elapsed monotonic time in milliseconds."""
    return round(
        (time.perf_counter() - started) * 1_000,
        2,
    )


execute_service_operation = execute_operation
execute_repository_operation = execute_operation


__all__ = [
    "execute_operation",
    "execute_repository_operation",
    "execute_service_operation",
    "execute_with_timeout",
]
