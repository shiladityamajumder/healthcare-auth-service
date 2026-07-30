"""File: app/core/logging.py

Purpose:
Configures queue-backed structured logging and central sensitive-value
redaction for application and infrastructure events.

Dependency flow:
Application event and named context
-> logger adapter and sanitization
-> queue handler/listener
-> configured output formatter

This is the existing logging foundation with authentication-specific redaction
keys and token-pattern protection added. Request bodies and identity secrets
must still never be logged deliberately.
"""

from __future__ import annotations

import atexit
import json
import logging
import logging.handlers
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime
from queue import Full, Queue
from threading import Lock
from typing import Any
from zoneinfo import ZoneInfo

from app.core.config import AppSettings, Environment, get_settings
from app.core.request_context import (
    get_correlation_id,
    get_request_id,
    get_trace_id,
)

_LOG_RECORD_BUILTINS = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
)
_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "clinical_data",
        "code",
        "connection_string",
        "cookie",
        "credentials",
        "database_url",
        "destination",
        "device_fingerprint",
        "diagnosis",
        "dsn",
        "email_password",
        "jwt",
        "medical_data",
        "mfa_encryption_key",
        "mfa_token",
        "otp",
        "otp_code",
        "otp_hash",
        "password",
        "password_hash",
        "patient",
        "patient_data",
        "prescription",
        "private_key",
        "refresh_token",
        "secret",
        "secret_hash",
        "set_cookie",
        "token",
    }
)
_AUTH_PATTERN = re.compile(
    r"(?i)\b(?:authorization|bearer)\b\s*[:=]?\s*[^\s,;]+"
)
_URI_PASSWORD_PATTERN = re.compile(r"(://[^:/\s]+:)([^@/\s]+)(@)")
_JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)

_log_queue: Queue[logging.LogRecord] | None = None
_listener: logging.handlers.QueueListener | None = None
_setup_lock = Lock()
_configured = False
_dropped_records = 0


def _redact_text(value: str) -> str:
    """Redact common credential patterns embedded in log strings."""
    value = _AUTH_PATTERN.sub("authorization=[REDACTED]", value)
    value = _URI_PASSWORD_PATTERN.sub(r"\1[REDACTED]\3", value)
    return _JWT_PATTERN.sub("[REDACTED_JWT]", value)


def sanitize_log_value(value: Any, *, key: str | None = None) -> Any:
    """Recursively sanitize structured log values.

    This is defense in depth, not permission to log authentication payloads,
    request bodies, healthcare records, or notification destinations.
    """
    if key and key.casefold() in _SENSITIVE_KEYS:
        return "[REDACTED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): sanitize_log_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return [sanitize_log_value(item) for item in value]
    return _redact_text(repr(value))


class ContextFilter(logging.Filter):
    """Capture context variables on the producer thread before queueing."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        record.correlation_id = get_correlation_id()
        record.trace_id = get_trace_id()
        return True


class NonBlockingQueueHandler(logging.handlers.QueueHandler):
    """Drop records instead of blocking the application when the queue is full."""

    def enqueue(self, record: logging.LogRecord) -> None:
        global _dropped_records
        try:
            self.queue.put_nowait(record)
        except Full:
            _dropped_records += 1
            if _dropped_records in {1, 10, 100} or _dropped_records % 1_000 == 0:
                sys.stderr.write(
                    "Logging queue is full; records are being dropped. "
                    f"dropped={_dropped_records}\n"
                )


class StructuredFormatter(logging.Formatter):
    """Render production JSON or readable local log lines."""

    def __init__(self, *, json_mode: bool, timezone_name: str) -> None:
        super().__init__()
        self._json_mode = json_mode
        self._timezone = ZoneInfo(timezone_name)

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(
            record.created,
            tz=self._timezone,
        ).isoformat()
        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": _redact_text(record.getMessage()),
            "request_id": getattr(record, "request_id", None),
            "correlation_id": getattr(record, "correlation_id", None),
            "trace_id": getattr(record, "trace_id", None),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        for key, value in record.__dict__.items():
            if key in _LOG_RECORD_BUILTINS or key in payload:
                continue
            payload[key] = sanitize_log_value(value, key=key)

        if record.exc_info:
            payload["exception"] = _redact_text(
                self.formatException(record.exc_info)
            )

        if self._json_mode:
            return json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )

        request_id = payload["request_id"] or "-"
        context = {
            key: value
            for key, value in payload.items()
            if key
            not in {
                "timestamp",
                "level",
                "logger",
                "message",
                "request_id",
                "correlation_id",
                "trace_id",
                "module",
                "function",
                "line",
                "exception",
            }
        }
        suffix = f" context={context}" if context else ""
        exception = f"\n{payload['exception']}" if "exception" in payload else ""
        return (
            f"{timestamp} | {record.levelname:<8} | {record.name} "
            f"[request_id={request_id}] | {payload['message']}"
            f"{suffix}{exception}"
        )


def setup_logging(settings: AppSettings | None = None) -> None:
    """Configure process logging exactly once."""
    global _configured, _listener, _log_queue
    with _setup_lock:
        if _configured:
            return

        resolved = settings or get_settings()
        root = logging.getLogger()
        root.setLevel(resolved.LOG_LEVEL.upper())
        root.handlers.clear()

        json_mode = resolved.LOG_JSON or (
            resolved.ENVIRONMENT == Environment.PRODUCTION
        )
        formatter = StructuredFormatter(
            json_mode=json_mode,
            timezone_name=resolved.TIMEZONE,
        )

        sinks: list[logging.Handler] = []
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        sinks.append(console)

        if resolved.LOG_TO_FILE:
            resolved.log_directory.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                resolved.log_directory / resolved.LOG_FILE,
                maxBytes=resolved.LOG_MAX_BYTES,
                backupCount=resolved.LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            sinks.append(file_handler)

        _log_queue = Queue(maxsize=resolved.LOG_QUEUE_SIZE)
        queue_handler = NonBlockingQueueHandler(_log_queue)
        queue_handler.addFilter(ContextFilter())
        root.addHandler(queue_handler)

        _listener = logging.handlers.QueueListener(
            _log_queue,
            *sinks,
            respect_handler_level=True,
        )
        _listener.start()
        _configured = True


def shutdown_logging() -> None:
    """Drain and stop the process logging listener."""
    global _configured, _listener, _log_queue
    with _setup_lock:
        if _listener is not None:
            _listener.stop()
        _listener = None
        _log_queue = None
        _configured = False


def get_logger(name: str) -> logging.Logger:
    """Return a standard library logger for ``name``."""
    return logging.getLogger(name)


atexit.register(shutdown_logging)

__all__ = [
    "ContextFilter",
    "NonBlockingQueueHandler",
    "StructuredFormatter",
    "get_logger",
    "sanitize_log_value",
    "setup_logging",
    "shutdown_logging",
]
