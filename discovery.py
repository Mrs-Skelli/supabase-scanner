import argparse
import asyncio
import json
import logging
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
from masking import EvidenceConfig, credential_preview, prepare_sample_data
from scanner import ScanResult, scan
from shodan_scanner import (
    RESULTS_DIR,
    SHODAN_QUERIES,
    _iter_shodan_targets,
    _shodan_client,
)

logger = logging.getLogger(__name__)


class ShodanDiscoveryUnavailable(RuntimeError):
    """Raised when every Shodan query fails before returning candidates."""


@dataclass
class DiscoveryTarget:
    url: str
    sources: set[str] = field(default_factory=set)
    metadata: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: defaultdict(list)
    )


def _normalize_url(url: str) -> str | None:
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _serialize_result(result: ScanResult, target: DiscoveryTarget) -> dict[str, Any]:
    evidence = EvidenceConfig.from_environment()
    sensitive_key_exposures = getattr(result, "sensitive_key_exposures", [])
    sensitive_key_exposure_count = sum(
        exposure.occurrence_count for exposure in sensitive_key_exposures
    )
    finding_count = len(result.vulnerable_tables) + sensitive_key_exposure_count
    status = "finding" if finding_count else "clean"
    if result.error:
        status = "error"
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": result.target_url,
        "status": status,
        "masked": not evidence.raw_values,
        "sample_mode": ("raw_secrets_redacted" if evidence.raw_values else "masked"),
        "auth_mode": result.auth_mode,
        "finding_count": finding_count,
        "sensitive_key_exposure_count": sensitive_key_exposure_count,
        "js_files_scanned": result.js_files_scanned,
        "error": result.error,
        "sources": sorted(target.sources),
        "source_metadata": {k: v for k, v in target.metadata.items()},
        "credentials": [
            {
                "supabase_url": c.supabase_url,
                "project_id": c.project_id,
                "anon_key_preview": credential_preview(c.anon_key),
                "source_file": c.source_file,
            }
            for c in result.credentials
        ],
        "sensitive_key_exposures": [
            {
                "key_type": exposure.key_type,
                "occurrence_count": exposure.occurrence_count,
                "source_file": exposure.source_file,
                "fingerprint": exposure.fingerprint,
            }
            for exposure in sensitive_key_exposures
        ],
        "tables_checked": [
            {
                "name": t.name,
                "row_count": t.row_count,
                "sample_columns": t.sample_columns,
                "rls_likely_disabled": t.rls_likely_disabled,
                "error": t.error,
                "sample_data": prepare_sample_data(
                    t.sample_data,
                    raw_values=evidence.raw_values,
                    limit=evidence.sample_limit,
                ),
            }
            for t in result.tables_checked
        ],
        "vulnerable_tables": [
            {
                "name": t.name,
                "row_count": t.row_count,
                "sample_columns": t.sample_columns,
                "sample_data": prepare_sample_data(
                    t.sample_data,
                    raw_values=evidence.raw_values,
                    limit=evidence.sample_limit,
                ),
            }
            for t in result.vulnerable_tables
        ],
    }


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")


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
                    {"url": norm, "source": "shodan", "metadata": {"query": query}}
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
    sources: list[str], max_per_source: int
) -> dict[str, DiscoveryTarget]:
    merged: dict[str, DiscoveryTarget] = {}

    async def add_many(items: list[dict[str, Any]]) -> None:
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
        try:
            await add_many(await discovery)
        except Exception as exc:  # noqa: BLE001 - third-party provider boundary
            # Provider exceptions may contain signed URLs or API credentials.
            logger.warning("%s discovery unavailable: %s", name, type(exc).__name__)

    if "shodan" in sources:
        await add_source("Shodan", _discover_shodan(max_per_source))
    if "commoncrawl" in sources:
        await add_source(
            "Common Crawl",
            commoncrawl_source.discover_targets(max_results=max_per_source),
        )
    if "builtwith" in sources:
        await add_source(
            "BuiltWith",
            builtwith_source.discover_targets(max_results=max_per_source),
        )
    return merged


async def _scan_batch(batch: list[DiscoveryTarget]) -> list[ScanResult]:
    tasks = [scan(item.url) for item in batch]
    return await asyncio.gather(*tasks, return_exceptions=False)


async def run_discovery_scan(
    sources: list[str],
    max_per_source: int,
    batch_size: int,
    findings_output: Path | None = None,
    inventory_output: Path | None = None,
) -> tuple[Path, Path]:
    if max_per_source < 1:
        raise ValueError("max_per_source must be at least 1")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    if findings_output is None:
        findings_output = RESULTS_DIR / f"findings_{ts}.jsonl"
    if inventory_output is None:
        inventory_output = RESULTS_DIR / f"inventory_{ts}.jsonl"

    targets = await discover_targets(sources, max_per_source)
    logger.info(
        "Discovered %d unique targets across sources: %s",
        len(targets),
        ", ".join(sources),
    )

    scanned = 0
    found_creds = 0
    found_findings = 0
    target_list = list(targets.values())
    for i in range(0, len(target_list), batch_size):
        batch = target_list[i : i + batch_size]
        results = await _scan_batch(batch)
        for target, result in zip(batch, results, strict=True):
            scanned += 1
            if result.found_credentials:
                found_creds += 1
            if result.has_reportable_findings:
                found_findings += 1
            record = _serialize_result(result, target)
            _append_jsonl(inventory_output, record)
            if result.has_reportable_findings:
                _append_jsonl(findings_output, record)
        logger.info(
            "Progress: %d/%d scanned | %d with public config | %d with findings",
            scanned,
            len(target_list),
            found_creds,
            found_findings,
        )

    logger.info(
        "Discovery scan complete. Findings: %s | Inventory: %s",
        findings_output,
        inventory_output,
    )
    return findings_output, inventory_output


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    parser = argparse.ArgumentParser(description="Unified Supabase discovery runner")
    parser.add_argument(
        "--sources",
        default="shodan,commoncrawl,builtwith",
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
    args = parser.parse_args()
    srcs = [s.strip() for s in args.sources.split(",") if s.strip()]
    asyncio.run(
        run_discovery_scan(
            srcs, args.max_per_source, args.batch, args.output, args.inventory_output
        )
    )
