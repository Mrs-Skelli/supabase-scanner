"""Read-only access to persisted scanner findings."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _record_timestamp(record: dict[str, Any]) -> str:
    timestamp = record.get("timestamp", "")
    return timestamp if isinstance(timestamp, str) else ""


def _nonnegative_int(value: Any) -> int:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else 0
    )


def load_latest_findings(results_dir: Path) -> list[dict[str, Any]]:
    """Load the newest valid JSONL record for each target."""
    latest: dict[str, dict[str, Any]] = {}
    for path in results_dir.glob("findings_*.jsonl"):
        try:
            with path.open(encoding="utf-8") as findings_file:
                for line_number, line in enumerate(findings_file, start=1):
                    if not (line := line.strip()):
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning(
                            "Ignoring malformed finding record",
                            extra={
                                "event": "finding_record_invalid",
                                "file": path.name,
                                "line": line_number,
                            },
                        )
                        continue
                    if not isinstance(record, dict):
                        continue
                    target = record.get("target")
                    timestamp = _record_timestamp(record)
                    if not isinstance(target, str) or not target:
                        continue
                    previous = latest.get(target)
                    if previous is None or timestamp >= _record_timestamp(previous):
                        latest[target] = record
        except OSError as exc:
            logger.warning(
                "Unable to read findings file",
                extra={
                    "event": "finding_file_unreadable",
                    "file": path.name,
                    "error_type": type(exc).__name__,
                },
            )

    return sorted(
        latest.values(),
        key=_record_timestamp,
        reverse=True,
    )


def summarize_finding(record: dict[str, Any]) -> dict[str, Any]:
    readable_tables = record.get("vulnerable_tables", []) or []
    sensitive_exposures = record.get("sensitive_key_exposures", []) or []
    return {
        "target": record.get("target"),
        "timestamp": record.get("timestamp"),
        "sources": record.get("sources", []),
        "discovery_confidence": record.get("discovery_confidence", "unknown"),
        "credential_count": len(record.get("credentials", []) or []),
        "sensitive_key_exposure_count": sum(
            _nonnegative_int(item.get("occurrence_count"))
            for item in sensitive_exposures
            if isinstance(item, dict)
        ),
        "vulnerable_table_count": len(readable_tables),
        "total_rows_exposed": sum(
            _nonnegative_int(table.get("row_count"))
            for table in readable_tables
            if isinstance(table, dict)
        ),
        "tables": [
            table.get("name") for table in readable_tables if isinstance(table, dict)
        ],
    }


def matches_query(record: dict[str, Any], query: str) -> bool:
    """Match target or readable-table names without assuming valid legacy rows."""
    needle = query.casefold()
    target = record.get("target", "")
    if isinstance(target, str) and needle in target.casefold():
        return True
    return any(
        needle in table.get("name", "").casefold()
        for table in record.get("vulnerable_tables", []) or []
        if isinstance(table, dict) and isinstance(table.get("name", ""), str)
    )
