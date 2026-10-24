"""
Shodan-powered internet-scale scan for sites using Supabase.
Queries Shodan for pages embedding supabase.co URLs, then feeds
each discovered target through the core scanner.
"""

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

import shodan

from masking import EvidenceConfig, credential_preview, prepare_sample_data
from scanner import ScanResult, scan

logger = logging.getLogger(__name__)


class ShodanSourceUnavailable(RuntimeError):
    """Raised when Shodan cannot return any first-page search results."""


# Shodan search query that finds pages referencing Supabase
# Multiple queries for maximum Supabase coverage
SHODAN_QUERIES = [
    'ssl.cert.subject.cn:"*.supabase.co"',  # Hosted Supabase (highest yield)
    'ssl.cert.subject.cn:"*.supabase.in"',  # Alternative Supabase domain
    'http.html:"supabase.co"',  # Frontend JS references
    'http.component:"PostgREST"',  # Self-hosted PostgREST
]
SHODAN_QUERY = SHODAN_QUERIES[0]  # Default for CLI --query

# Output directory for findings
RESULTS_DIR = Path("results")


def _shodan_client() -> shodan.Shodan:
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY environment variable not set")
    return shodan.Shodan(api_key)


def _iter_shodan_targets(api: shodan.Shodan, query: str, max_results: int):
    """
    Yield URLs from Shodan search results.
    Uses api.search() (free tier compatible, 100 results per page).
    Falls back to search_cursor if available.
    """
    count = 0
    page = 1
    while count < max_results:
        try:
            results = api.search(query, page=page)
        except shodan.APIError:
            if page == 1:
                raise
            logger.warning("Shodan pagination stopped: APIError")
            break

        matches = results.get("matches", [])
        if not matches:
            break

        for banner in matches:
            if count >= max_results:
                break
            ip = banner.get("ip_str", "")
            port = banner.get("port", 443)
            hostnames = banner.get("hostnames", [])
            http_host = banner.get("http", {}).get("host", "")

            host = http_host or (hostnames[0] if hostnames else ip)
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{host}"
            if port not in (80, 443, 8080, 8443):
                url += f":{port}"

            yield url
            count += 1

        page += 1


async def _scan_batch(urls: list[str]) -> list[ScanResult]:
    """Scan a batch of URLs concurrently."""
    tasks = [scan(url) for url in urls]
    return await asyncio.gather(*tasks, return_exceptions=False)


def _save_finding(result: ScanResult, output_file: Path) -> None:
    """Append independently reportable, safely serialized evidence."""
    evidence = EvidenceConfig.from_environment()
    sensitive_key_exposure_count = sum(
        exposure.occurrence_count for exposure in result.sensitive_key_exposures
    )
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": result.target_url,
        "masked": not evidence.raw_values,
        "sample_mode": ("raw_secrets_redacted" if evidence.raw_values else "masked"),
        "finding_count": len(result.vulnerable_tables) + sensitive_key_exposure_count,
        "sensitive_key_exposure_count": sensitive_key_exposure_count,
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
            for exposure in result.sensitive_key_exposures
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
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")


async def run_shodan_scan(
    query: str = SHODAN_QUERY,
    max_results: int = 1000,
    batch_size: int = 10,
    output_path: Path | None = None,
):
    """
    Main entry point for internet-scale scanning via Shodan.

    Args:
        query:       Shodan dork to use
        max_results: Cap on how many Shodan results to process
        batch_size:  Concurrent scans per batch
        output_path: JSONL file to write findings to
    """
    if max_results < 1:
        raise ValueError("max_results must be at least 1")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")

    RESULTS_DIR.mkdir(exist_ok=True)
    if output_path is None:
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        output_path = RESULTS_DIR / f"findings_{ts}.jsonl"

    api = _shodan_client()

    # Count results first
    try:
        info = api.count(query)
        total = min(info["total"], max_results)
        logger.info(
            "Shodan reports %d results for query (scanning up to %d)",
            info["total"],
            total,
        )
    except shodan.APIError:
        logger.error("Shodan count failed: APIError")
        raise ShodanSourceUnavailable("Shodan count request failed") from None

    # Run all queries and deduplicate URLs
    all_urls = []
    seen = set()
    failed_queries = 0
    queries = SHODAN_QUERIES if query == SHODAN_QUERIES[0] else [query]
    for q in queries:
        try:
            for url in _iter_shodan_targets(api, q, max_results):
                if url not in seen:
                    seen.add(url)
                    all_urls.append(url)
        except shodan.APIError:
            failed_queries += 1
            logger.warning("Shodan query failed: APIError")
    if failed_queries == len(queries) and not all_urls:
        raise ShodanSourceUnavailable("all Shodan search queries failed")
    urls = all_urls[:max_results]
    logger.info(
        "Collected %d unique URLs from %d Shodan queries", len(urls), len(queries)
    )

    scanned = 0
    found_creds = 0
    found_findings = 0

    for i in range(0, len(urls), batch_size):
        batch = urls[i : i + batch_size]
        results = await _scan_batch(batch)

        for result in results:
            scanned += 1
            if result.found_credentials:
                found_creds += 1
                logger.info(
                    "[PUBLIC CONFIG] %s — project: %s",
                    result.target_url,
                    result.credentials[0].project_id,
                )
            if result.has_reportable_findings:
                found_findings += 1
                logger.warning(
                    "[FINDING] %s — %d readable tables, %d sensitive key exposures",
                    result.target_url,
                    len(result.vulnerable_tables),
                    sum(
                        exposure.occurrence_count
                        for exposure in result.sensitive_key_exposures
                    ),
                )
                _save_finding(result, output_path)

        logger.info(
            "Progress: %d/%d scanned | %d with public config | %d with findings",
            scanned,
            len(urls),
            found_creds,
            found_findings,
        )

    logger.info("Scan complete. Findings saved to %s", output_path)
    return output_path


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(description="Shodan-powered Supabase RLS scanner")
    parser.add_argument("--query", default=SHODAN_QUERY, help="Shodan search query")
    parser.add_argument("--max", type=int, default=1000, help="Max results to process")
    parser.add_argument(
        "--batch", type=int, default=10, help="Concurrent scans per batch"
    )
    parser.add_argument("--output", type=Path, help="Output JSONL file path")
    args = parser.parse_args()

    asyncio.run(
        run_shodan_scan(
            query=args.query,
            max_results=args.max,
            batch_size=args.batch,
            output_path=args.output,
        )
    )
