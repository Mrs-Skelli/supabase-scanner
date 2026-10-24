import argparse
import asyncio
import logging
import os
import time
from collections import defaultdict
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import shodan

import builtwith_source
import commoncrawl_source
import urlscan_source
from finding_records import append_jsonl, serialize_evidence
from masking import EvidenceConfig
from observability import (
    bind_operation,
    configure_logging,
    new_id,
    record_error,
    reset_operation,
    utc_now,
    write_status_file,
)
from scan_batch import scan_urls
from scan_models import ScanResult
from scanner import scan
from shodan_scanner import (
    RESULTS_DIR,
    SHODAN_QUERIES,
    _iter_shodan_targets,
    _shodan_client,
    shodan_query_confidence,
)

logger = logging.getLogger(__name__)
DISCOVERY_STATUS_FILE = RESULTS_DIR / "diagnostics" / "discovery-status.json"
SUPPORTED_SOURCES = frozenset({"shodan", "commoncrawl", "builtwith", "urlscan"})


class ShodanDiscoveryUnavailable(RuntimeError):
    """Raised when every Shodan query fails before returning candidates."""


class DiscoveryProvidersUnavailable(RuntimeError):
    """Raised when no enabled discovery provider can complete a refresh."""


@dataclass
class DiscoveryTarget:
    url: str
    sources: set[str] = field(default_factory=set)
    metadata: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: defaultdict(list)
    )


@dataclass
class DiscoveryRunState:
    """Mutable counters and derived status for one discovery execution."""

    sources: list[str]
    run_id: str = field(default_factory=lambda: new_id("discovery"))
    started_at: str = field(default_factory=utc_now)
    started_monotonic: float = field(default_factory=time.perf_counter)
    providers: dict[str, dict[str, Any]] = field(default_factory=dict)
    candidates: int = 0
    scanned: int = 0
    public_configs: int = 0
    findings: int = 0

    def elapsed_ms(self) -> float:
        return round((time.perf_counter() - self.started_monotonic) * 1000, 2)

    def payload(self, status: str, error_type: str | None = None) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": status,
            "started_at": self.started_at,
            "finished_at": None if status == "running" else utc_now(),
            "duration_ms": None if status == "running" else self.elapsed_ms(),
            "sources": self.sources,
            "providers": self.providers,
            "candidates": self.candidates,
            "scanned": self.scanned,
            "public_configs": self.public_configs,
            "findings": self.findings,
            "error_type": error_type,
        }

    def persist(
        self,
        path: Path,
        status: str,
        error_type: str | None = None,
    ) -> None:
        try:
            write_status_file(path, self.payload(status, error_type))
        except OSError as exc:
            logger.warning(
                "Unable to write discovery status",
                extra={
                    "event": "status_write_failed",
                    "error_type": type(exc).__name__,
                },
            )


_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def _run_outcome(
    *,
    active_scan: bool,
    candidate_count: int,
    provider_status: dict[str, dict[str, Any]],
) -> str:
    """Summarize provider health without presenting failed refreshes as success."""
    statuses = {item.get("status") for item in provider_status.values()}
    has_errors = "error" in statuses
    has_healthy_provider = "ok" in statuses

    if candidate_count:
        if has_errors:
            return "partial"
        return "completed" if active_scan else "discovered"
    if has_healthy_provider:
        return "partial" if has_errors else "empty"
    if has_errors:
        return "failed"
    if statuses == {"disabled"}:
        return "disabled"
    return "empty"


def _target_confidence(target: DiscoveryTarget) -> str:
    confidence = "low"
    for entries in target.metadata.values():
        for entry in entries:
            candidate = entry.get("confidence")
            if _CONFIDENCE_RANK.get(candidate, 0) > _CONFIDENCE_RANK[confidence]:
                confidence = candidate
    return confidence


def _normalize_url(url: str) -> str | None:
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _serialize_result(result: ScanResult, target: DiscoveryTarget) -> dict[str, Any]:
    evidence = EvidenceConfig.from_environment()
    status = "finding" if result.has_reportable_findings else "clean"
    if result.error:
        status = "error"
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": result.target_url,
        "status": status,
        "auth_mode": result.auth_mode,
        "js_files_scanned": result.js_files_scanned,
        "error": result.error,
        "discovery_confidence": _target_confidence(target),
        "sources": sorted(target.sources),
        "source_metadata": dict(target.metadata),
    }
    record.update(serialize_evidence(result, evidence, include_tables_checked=True))
    return record


def _serialize_candidate(target: DiscoveryTarget) -> dict[str, Any]:
    """Serialize passive lead metadata without probing the target."""
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": target.url,
        "status": "candidate",
        "discovery_confidence": _target_confidence(target),
        "sources": sorted(target.sources),
        "source_metadata": dict(target.metadata),
    }


async def _discover_shodan(max_results: int) -> list[dict[str, Any]]:
    api = _shodan_client()
    seen = set()
    results = []
    failed_queries = 0
    per_query = max(1, max_results // max(1, len(SHODAN_QUERIES)))
    for query in SHODAN_QUERIES:
        try:
            for url in _iter_shodan_targets(api, query, per_query):
                norm = _normalize_url(url)
                if not norm or norm in seen:
                    continue
                seen.add(norm)
                results.append(
                    {
                        "url": norm,
                        "source": "shodan",
                        "metadata": {
                            "query": query,
                            "confidence": shodan_query_confidence(query),
                        },
                    }
                )
                if len(results) >= max_results:
                    return results
        except shodan.APIError:
            failed_queries += 1
            logger.warning("Shodan discovery query unavailable: APIError")
    if failed_queries == len(SHODAN_QUERIES) and not results:
        raise ShodanDiscoveryUnavailable("all Shodan queries failed")
    return results


async def discover_targets(
    sources: list[str],
    max_per_source: int,
    provider_status: dict[str, dict[str, Any]] | None = None,
) -> dict[str, DiscoveryTarget]:
    unknown_sources = sorted(set(sources) - SUPPORTED_SOURCES)
    if unknown_sources:
        raise ValueError(f"unknown discovery source(s): {', '.join(unknown_sources)}")
    if not sources:
        raise ValueError("at least one discovery source is required")

    merged: dict[str, DiscoveryTarget] = {}

    def add_many(items: list[dict[str, Any]]) -> None:
        for item in items:
            norm = _normalize_url(item.get("url", ""))
            if not norm:
                continue
            target = merged.setdefault(norm, DiscoveryTarget(url=norm))
            source = item.get("source", "unknown")
            target.sources.add(source)
            meta = item.get("metadata") or {}
            target.metadata[source].append(meta)

    async def add_source(name: str, discovery: Awaitable[list[dict[str, Any]]]) -> None:
        """Keep one unavailable provider from aborting the complete run."""
        provider_key = name.lower().replace(" ", "_")
        try:
            items = await discovery
            add_many(items)
            status = "ok"
            error_type = None
            if name == "BuiltWith" and not os.getenv("BUILTWITH_API_KEY"):
                status = "disabled"
                error_type = "MissingConfiguration"
            if provider_status is not None:
                provider_status[provider_key] = {
                    "status": status,
                    "candidates": len(items),
                    "error_type": error_type,
                }
        except Exception as exc:
            # Provider exceptions may contain signed URLs or API credentials.
            error_type = type(exc).__name__
            if provider_status is not None:
                provider_status[provider_key] = {
                    "status": "error",
                    "candidates": 0,
                    "error_type": error_type,
                }
            record_error("discovery", error_type, "provider_unavailable")
            logger.warning(
                "Discovery provider unavailable",
                extra={
                    "event": "provider_unavailable",
                    "provider": provider_key,
                    "error_type": error_type,
                },
            )

    jobs: list[Awaitable[None]] = []
    if "shodan" in sources:
        jobs.append(add_source("Shodan", _discover_shodan(max_per_source)))
    if "commoncrawl" in sources:
        jobs.append(
            add_source(
                "Common Crawl",
                commoncrawl_source.discover_targets(max_results=max_per_source),
            )
        )
    if "builtwith" in sources:
        jobs.append(
            add_source(
                "BuiltWith",
                builtwith_source.discover_targets(max_results=max_per_source),
            )
        )
    if "urlscan" in sources:
        jobs.append(
            add_source(
                "URLScan",
                urlscan_source.discover_targets(max_results=max_per_source),
            )
        )
    await asyncio.gather(*jobs)
    return merged


async def _scan_batch(batch: list[DiscoveryTarget]) -> list[ScanResult]:
    return await scan_urls((target.url for target in batch), scan, logger)


async def run_discovery_scan(
    sources: list[str],
    max_per_source: int,
    batch_size: int,
    findings_output: Path | None = None,
    inventory_output: Path | None = None,
    active_scan: bool = True,
) -> tuple[Path, Path]:
    if max_per_source < 1:
        raise ValueError("max_per_source must be at least 1")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    RESULTS_DIR.mkdir(exist_ok=True)
    state = DiscoveryRunState(sources=sources)
    operation_token = bind_operation(state.run_id)
    state.persist(DISCOVERY_STATUS_FILE, "running")
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    if findings_output is None:
        findings_output = RESULTS_DIR / f"findings_{ts}.jsonl"
    if inventory_output is None:
        inventory_output = RESULTS_DIR / f"inventory_{ts}.jsonl"

    logger.info(
        "Discovery run started",
        extra={
            "event": "discovery_started",
            "source_count": len(sources),
            "max_per_source": max_per_source,
            "batch_size": batch_size,
        },
    )
    try:
        targets = await discover_targets(sources, max_per_source, state.providers)
        target_list = list(targets.values())
        state.candidates = len(target_list)
        logger.info(
            "Discovery candidates collected",
            extra={"event": "candidates_collected", "candidates": len(target_list)},
        )

        outcome = _run_outcome(
            active_scan=active_scan,
            candidate_count=state.candidates,
            provider_status=state.providers,
        )
        if outcome in {"failed", "disabled"}:
            raise DiscoveryProvidersUnavailable(
                "no enabled discovery provider completed successfully"
            )

        if not active_scan:
            for target in target_list:
                append_jsonl(inventory_output, _serialize_candidate(target))
            state.persist(DISCOVERY_STATUS_FILE, outcome)
            logger.info(
                "Passive discovery completed",
                extra={
                    "event": "passive_discovery_completed",
                    "status": outcome,
                    "duration_ms": state.elapsed_ms(),
                    "candidates": len(target_list),
                },
            )
            return findings_output, inventory_output

        for i in range(0, len(target_list), batch_size):
            batch = target_list[i : i + batch_size]
            results = await _scan_batch(batch)
            for target, result in zip(batch, results, strict=True):
                state.scanned += 1
                if result.found_credentials:
                    state.public_configs += 1
                if result.has_reportable_findings:
                    state.findings += 1
                record = _serialize_result(result, target)
                append_jsonl(inventory_output, record)
                if result.has_reportable_findings:
                    append_jsonl(findings_output, record)
            logger.info(
                "Discovery batch completed",
                extra={
                    "event": "discovery_progress",
                    "scanned": state.scanned,
                    "candidates": len(target_list),
                    "public_configs": state.public_configs,
                    "findings": state.findings,
                },
            )

        state.persist(DISCOVERY_STATUS_FILE, outcome)
        logger.info(
            "Discovery run completed",
            extra={
                "event": "discovery_completed",
                "status": outcome,
                "duration_ms": state.elapsed_ms(),
                "candidates": len(target_list),
                "scanned": state.scanned,
                "public_configs": state.public_configs,
                "findings": state.findings,
            },
        )
        return findings_output, inventory_output
    except Exception as exc:
        error_type = type(exc).__name__
        record_error("discovery", error_type, "discovery_failed")
        state.persist(DISCOVERY_STATUS_FILE, "failed", error_type)
        logger.exception(
            "Discovery run failed",
            extra={"event": "discovery_failed", "error_type": error_type},
        )
        raise
    finally:
        reset_operation(operation_token)


if __name__ == "__main__":
    configure_logging("discovery", Path(__file__).resolve().parent)
    parser = argparse.ArgumentParser(description="Unified Supabase discovery runner")
    parser.add_argument(
        "--sources",
        default="shodan,commoncrawl,builtwith,urlscan",
        help="Comma-separated sources to run",
    )
    parser.add_argument(
        "--max-per-source",
        type=int,
        default=1000,
        help="Max targets to ingest from each source",
    )
    parser.add_argument(
        "--batch", type=int, default=10, help="Concurrent scans per batch"
    )
    parser.add_argument(
        "--output", type=Path, help="Vulnerable findings JSONL output path"
    )
    parser.add_argument(
        "--inventory-output", type=Path, help="All scanned targets JSONL output path"
    )
    parser.add_argument(
        "--discover-only",
        action="store_true",
        help="Collect and de-duplicate passive candidates without probing targets",
    )
    args = parser.parse_args()
    srcs = [s.strip() for s in args.sources.split(",") if s.strip()]
    asyncio.run(
        run_discovery_scan(
            srcs,
            args.max_per_source,
            args.batch,
            args.output,
            args.inventory_output,
            active_scan=not args.discover_only,
        )
    )
