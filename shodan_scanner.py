"""
Shodan-powered internet-scale scan for sites using Supabase.
Queries Shodan for pages embedding supabase.co URLs, then feeds
each discovered target through the core scanner.
"""

import asyncio
import csv
import json
import logging
import os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

import shodan

from scanner import ScanResult, scan

logger = logging.getLogger(__name__)

# Shodan search query that finds pages referencing Supabase
# Multiple queries for maximum Supabase coverage
SHODAN_QUERIES = [
    'ssl.cert.subject.cn:"*.supabase.co"',       # Hosted Supabase (highest yield)
    'ssl.cert.subject.cn:"*.supabase.in"',        # Alternative Supabase domain
    'http.html:"supabase.co"',                    # Frontend JS references
    'http.component:"PostgREST"',                 # Self-hosted PostgREST
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
    try:
        # Free tier: use paginated search (100 results per page)
        page = 1
        while count < max_results:
            try:
                results = api.search(query, page=page)
            except shodan.APIError as exc:
                if page == 1:
                    logger.error("Shodan search error: %s", exc)
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
    except shodan.APIError as exc:
        logger.error("Shodan API error: %s", exc)


async def _scan_batch(urls: list[str]) -> list[ScanResult]:
    """Scan a batch of URLs concurrently."""
    tasks = [scan(url) for url in urls]
    return await asyncio.gather(*tasks, return_exceptions=False)


def _save_finding(result: ScanResult, output_file: Path):
    """Append a vulnerable finding to the JSONL output file."""
    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "target": result.target_url,
        "credentials": [
            {
                "supabase_url": c.supabase_url,
                "project_id": c.project_id,
                "anon_key": c.anon_key,
                "source_file": c.source_file,
            }
            for c in result.credentials
        ],
        "vulnerable_tables": [
            {
                "name": t.name,
                "row_count": t.row_count,
                "sample_columns": t.sample_columns,
            }
            for t in result.vulnerable_tables
        ],
    }
    with output_file.open("a") as f:
        f.write(json.dumps(record) + "\n")


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
    RESULTS_DIR.mkdir(exist_ok=True)
    if output_path is None:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = RESULTS_DIR / f"findings_{ts}.jsonl"

    api = _shodan_client()

    # Count results first
    try:
        info = api.count(query)
        total = min(info["total"], max_results)
        logger.info("Shodan reports %d results for query (scanning up to %d)", info["total"], total)
    except shodan.APIError as exc:
        logger.error("Shodan count failed: %s", exc)
        return

    # Run all queries and deduplicate URLs
    all_urls = []
    seen = set()
    queries = SHODAN_QUERIES if query == SHODAN_QUERIES[0] else [query]
    for q in queries:
        try:
            for url in _iter_shodan_targets(api, q, max_results):
                if url not in seen:
                    seen.add(url)
                    all_urls.append(url)
        except Exception as exc:
            logger.warning("Query failed '%s': %s", q, exc)
    urls = all_urls[:max_results]
    logger.info("Collected %d unique URLs from %d Shodan queries", len(urls), len(queries))

    scanned = 0
    found_creds = 0
    found_vuln = 0

    for i in range(0, len(urls), batch_size):
        batch = urls[i : i + batch_size]
        results = await _scan_batch(batch)

        for result in results:
            scanned += 1
            if result.found_credentials:
                found_creds += 1
                logger.info("[CREDS] %s — project: %s",
                            result.target_url,
                            result.credentials[0].project_id)
            if result.vulnerable_tables:
                found_vuln += 1
                logger.warning("[VULN] %s — %d tables exposed: %s",
                               result.target_url,
                               len(result.vulnerable_tables),
                               [t.name for t in result.vulnerable_tables])
                _save_finding(result, output_path)

        logger.info("Progress: %d/%d scanned | %d with creds | %d vulnerable",
                    scanned, len(urls), found_creds, found_vuln)

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
    parser.add_argument("--batch", type=int, default=10, help="Concurrent scans per batch")
    parser.add_argument("--output", type=Path, help="Output JSONL file path")
    args = parser.parse_args()

    asyncio.run(run_shodan_scan(
        query=args.query,
        max_results=args.max,
        batch_size=args.batch,
        output_path=args.output,
    ))
