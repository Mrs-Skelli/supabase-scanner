"""Secret-safe structured logging and lightweight runtime diagnostics."""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from collections import Counter, deque
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Lock
from typing import Any

REQUEST_ID: ContextVar[str] = ContextVar("request_id", default="-")
OPERATION_ID: ContextVar[str] = ContextVar("operation_id", default="-")

_STARTED_MONOTONIC = time.monotonic()
_STARTED_AT = datetime.now(UTC).isoformat()
_COUNTERS: Counter[str] = Counter()
_RECENT_ERRORS: deque[dict[str, str]] = deque(maxlen=25)
_STATE_LOCK = Lock()

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_SUPABASE_KEY_RE = re.compile(r"sb_(?:publishable|secret)_[A-Za-z0-9_-]{16,}")
_AUTH_RE = re.compile(
    r"(?i)(authorization|apikey|api[_-]?key|access[_-]?token|refresh[_-]?token)"
    r"(\s*[:=]\s*)([^\s,;&]+)"
)
_URL_SECRET_RE = re.compile(
    r"(?i)([?&](?:key|token|apikey|api_key|access_token|refresh_token)=)[^&#\s]+"
)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")
_NOISY_NETWORK_LOGGERS = ("httpx", "httpcore")

_STANDARD_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__) | frozenset(
    {
        "message",
        "asctime",
        "request_id",
        "operation_id",
        "component",
    }
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def normalize_request_id(value: str | None) -> str:
    if value and _SAFE_ID_RE.fullmatch(value):
        return value
    return new_id("req")


def redact_log_text(value: Any) -> str:
    """Remove reusable credentials from log messages and tracebacks."""
    text = str(value)
    text = _JWT_RE.sub("[jwt-redacted]", text)
    text = _SUPABASE_KEY_RE.sub("[supabase-key-redacted]", text)
    text = _AUTH_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[redacted]", text
    )
    return _URL_SECRET_RE.sub(lambda match: f"{match.group(1)}[redacted]", text)


def safe_exception_text(
    exc_info: tuple[type[BaseException], BaseException, Any],
) -> str:
    """Retain stack locations and exception type, but not runtime values."""
    exc_type, _exc_value, exc_traceback = exc_info
    frames: list[str] = []
    while exc_traceback is not None:
        frame = exc_traceback.tb_frame
        frames.append(
            f'  File "{frame.f_code.co_filename}", line {exc_traceback.tb_lineno}, '
            f"in {frame.f_code.co_name}"
        )
        exc_traceback = exc_traceback.tb_next
    return (
        "Traceback (most recent call last):\n"
        + "\n".join(frames)
        + (f"\n{exc_type.__name__}")
    )


class ContextFilter(logging.Filter):
    def __init__(self, component: str):
        super().__init__()
        self.component = component

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = REQUEST_ID.get()
        record.operation_id = OPERATION_ID.get()
        record.component = self.component
        return True


class SafeJsonFormatter(logging.Formatter):
    """Render one JSON object per line and redact message/traceback content."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "component": getattr(record, "component", "unknown"),
            "logger": record.name,
            "event": getattr(record, "event", "log"),
            "message": redact_log_text(record.getMessage()),
            "request_id": getattr(record, "request_id", "-"),
            "operation_id": getattr(record, "operation_id", "-"),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_FIELDS or key.startswith("_"):
                continue
            if key in {"msg", "args", "exc_info", "exc_text", "stack_info"}:
                continue
            if isinstance(value, (str, int, float, bool)) or value is None:
                payload[key] = (
                    redact_log_text(value) if isinstance(value, str) else value
                )
        if record.exc_info:
            payload["exception"] = safe_exception_text(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


class SafeTextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = redact_log_text(record.getMessage())
        prefix = (
            f"{datetime.fromtimestamp(record.created, UTC).isoformat()} "
            f"{record.levelname} {getattr(record, 'component', 'unknown')} "
            f"request={getattr(record, 'request_id', '-')} "
            f"operation={getattr(record, 'operation_id', '-')}"
        )
        if record.exc_info:
            traceback_text = safe_exception_text(record.exc_info)
            return f"{prefix} {message}\n{traceback_text}"
        return f"{prefix} {message}"


def _integer_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def configure_logging(component: str, base_dir: Path | None = None) -> Path | None:
    """Configure stderr plus a bounded rotating component log."""
    level_name = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    formatter: logging.Formatter
    if os.getenv("LOG_FORMAT", "json").strip().lower() == "text":
        formatter = SafeTextFormatter()
    else:
        formatter = SafeJsonFormatter()

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    for logger_name in _NOISY_NETWORK_LOGGERS:
        # These clients include full request URLs in normal log messages. Our
        # callers emit safe error classes and counters at the request boundary.
        logging.getLogger(logger_name).setLevel(logging.CRITICAL + 1)

    context_filter = ContextFilter(component)
    stream = logging.StreamHandler()
    stream.setLevel(level)
    stream.addFilter(context_filter)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    if os.getenv("LOG_TO_FILE", "true").strip().lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return None

    root_dir = base_dir or Path.cwd()
    configured_dir = os.getenv("LOG_DIR")
    log_dir = Path(configured_dir) if configured_dir else root_dir / "results" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{component}.log"
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=_integer_env(
            "LOG_MAX_BYTES", 5 * 1024 * 1024, 64 * 1024, 100 * 1024 * 1024
        ),
        backupCount=_integer_env("LOG_BACKUP_COUNT", 5, 1, 20),
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.addFilter(context_filter)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    return log_file


def bind_request(request_id: str) -> Token[str]:
    return REQUEST_ID.set(request_id)


def reset_request(token: Token[str]) -> None:
    REQUEST_ID.reset(token)


def bind_operation(operation_id: str) -> Token[str]:
    return OPERATION_ID.set(operation_id)


def reset_operation(token: Token[str]) -> None:
    OPERATION_ID.reset(token)


def increment_counter(name: str, amount: int = 1) -> None:
    with _STATE_LOCK:
        _COUNTERS[name] += amount


def record_error(component: str, error_type: str, event: str) -> None:
    increment_counter("errors_total")
    with _STATE_LOCK:
        _RECENT_ERRORS.append(
            {
                "timestamp": utc_now(),
                "component": component,
                "error_type": error_type,
                "event": event,
                "request_id": REQUEST_ID.get(),
                "operation_id": OPERATION_ID.get(),
            }
        )


def runtime_snapshot() -> dict[str, Any]:
    with _STATE_LOCK:
        counters = dict(sorted(_COUNTERS.items()))
        recent_errors = list(_RECENT_ERRORS)
    return {
        "started_at": _STARTED_AT,
        "uptime_seconds": round(time.monotonic() - _STARTED_MONOTONIC, 3),
        "counters": counters,
        "recent_errors": recent_errors,
        "log_level": logging.getLevelName(logging.getLogger().getEffectiveLevel()),
    }


def write_status_file(path: Path, payload: dict[str, Any]) -> None:
    """Atomically persist derived operational status without raw evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    temporary.replace(path)


def read_status_file(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None
