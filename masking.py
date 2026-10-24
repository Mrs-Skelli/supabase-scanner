"""Evidence handling for sample rows pulled from Supabase instances.

Masked previews remain the default. An explicit analyst mode can retain bounded
raw application values for severity review, while secret-shaped fields and
token values remain redacted.
"""
from __future__ import annotations

import re
from typing import Any

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.")
_LONG_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-/+=]{40,}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_DIGITS_RE = re.compile(r"\d")

# key-name hints that force masking regardless of value shape
_SENSITIVE_KEY_RE = re.compile(
    r"pass|secret|token|key|hash|ssn|social|card|cvv|iban|account|routing|"
    r"balance|salary|dob|birth|phone|address|email|api",
    re.I,
)

_SECRET_KEY_RE = re.compile(
    r"pass(word)?|secret|token|api[_-]?key|service[_-]?key|private[_-]?key|"
    r"authorization|cookie|session|credential|jwt|hash",
    re.I,
)

SECRET_REDACTION = "‹secret redacted›"


def _mask_email(v: str) -> str:
    name, _, domain = v.partition("@")
    head = name[0] if name else "?"
    return f"{head}{'*' * max(2, len(name) - 1)}@{domain}"


def _mask_str(v: str) -> str:
    if _EMAIL_RE.match(v):
        return _mask_email(v)
    if _JWT_RE.match(v):
        return "‹jwt redacted›"
    if _UUID_RE.match(v):
        return v[:8] + "‹…uuid›"
    if _LONG_TOKEN_RE.match(v):
        return f"‹token redacted:{len(v)} chars›"
    if len(v) > 48:
        return v[:12] + f"…‹+{len(v) - 12} chars›"
    # short free-text: keep first char, redact the rest so shape is visible
    if len(v) > 3:
        return v[0] + "•" * (len(v) - 1)
    return "•" * len(v)


def mask_value(key: str, v: Any) -> Any:
    """Redact a single value, preserving type/shape signal for triage."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        # numbers are often balances / ids / phone — show magnitude only
        s = str(abs(int(v))) if isinstance(v, int) else str(v)
        digits = sum(c.isdigit() for c in s)
        return f"‹num:{digits}d›"
    if isinstance(v, str):
        if _SENSITIVE_KEY_RE.search(key) and _DIGITS_RE.search(v):
            return f"‹redacted:{len(v)}›"
        return _mask_str(v)
    if isinstance(v, list):
        return f"‹list:{len(v)}›"
    if isinstance(v, dict):
        return {k: mask_value(k, sub) for k, sub in v.items()}
    return "‹redacted›"


def mask_row(row: dict) -> dict:
    if not isinstance(row, dict):
        return {}
    return {k: mask_value(k, v) for k, v in row.items()}


def mask_sample_data(rows: list, limit: int = 1) -> list:
    """Return at most `limit` masked rows (default 1 — proof, not a dump)."""
    if not isinstance(rows, list):
        return []
    return [mask_row(r) for r in rows[:limit] if isinstance(r, dict)]


def redact_secret_value(key: str, value: Any) -> Any:
    """Preserve application evidence while removing credentials and tokens."""
    if _SECRET_KEY_RE.search(key):
        return SECRET_REDACTION
    if isinstance(value, str):
        if _JWT_RE.match(value) or _LONG_TOKEN_RE.match(value):
            return SECRET_REDACTION
        return value
    if isinstance(value, list):
        return [redact_secret_value("", item) for item in value]
    if isinstance(value, dict):
        return {nested_key: redact_secret_value(nested_key, item)
                for nested_key, item in value.items()}
    return value


def raw_sample_data(rows: list, limit: int = 1) -> list:
    """Return bounded raw rows with secret-shaped values removed."""
    if not isinstance(rows, list):
        return []
    return [
        {key: redact_secret_value(key, value) for key, value in row.items()}
        for row in rows[:limit]
        if isinstance(row, dict)
    ]


def prepare_sample_data(rows: list, raw_values: bool, limit: int = 1) -> list:
    """Prepare bounded samples for storage or display in the requested mode."""
    safe_limit = max(1, min(int(limit), 3))
    if raw_values:
        return raw_sample_data(rows, limit=safe_limit)
    return mask_sample_data(rows, limit=safe_limit)
