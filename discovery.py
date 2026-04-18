import argparse
import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from scanner import scan, ScanResult
from shodan_scanner import RESULTS_DIR, SHODAN_QUERIES, _iter_shodan_targets, _shodan_client
import builtwith_source
import commoncrawl_source

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryTarget:
    url: str
    sources: set[str] = field(default_factory=set)
    metadata: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))


def _normalize_url(url: str) -> str | None:
    if not url:
        return None
    parsed = urlparse(url if '://' in url else f'https://{url}')
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return None
    return f'{parsed.scheme}://{parsed.netloc}'


def _serialize_result(result: ScanResult, target: DiscoveryTarget) -> dict[str, Any]:
    status = 'vulnerable' if result.vulnerable_tables else 'clean'
    if result.error:
        status = 'error'
    return {
        'timestamp': datetime.utcnow().isoformat(),
        'target': result.target_url,
        'status': status,
        'auth_mode': result.auth_mode,
        'js_files_scanned': result.js_files_scanned,
        'error': result.error,
        'sources': sorted(target.sources),
        'source_metadata': {k: v for k, v in target.metadata.items()},
        'credentials': [
            {
                'supabase_url': c.supabase_url,
                'project_id': c.project_id,
                'anon_key': c.anon_key,
                'source_file': c.source_file,
            }
            for c in result.credentials
        ],
        'tables_checked': [
            {
                'name': t.name,
                'row_count': t.row_count,
                'sample_columns': t.sample_columns,
                'rls_likely_disabled': t.rls_likely_disabled,
                'error': t.error,
                'sample_data': t.sample_data,
            }
            for t in result.tables_checked
        ],
        'vulnerable_tables': [
            {
                'name': t.name,
                'row_count': t.row_count,
                'sample_columns': t.sample_columns,
                'sample_data': t.sample_data,
            }
            for t in result.vulnerable_tables
        ],
    }


def _append_jsonl(path: Path, record: dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as f:
        f.write(json.dumps(record) + '\n')


async def _discover_shodan(max_results: int) -> list[dict[str, Any]]:
    api = _shodan_client()
    seen = set()
    results = []
    per_query = max(1, max_results // max(1, len(SHODAN_QUERIES)))
    for query in SHODAN_QUERIES:
        try:
            for url in _iter_shodan_targets(api, query, per_query):
                norm = _normalize_url(url)
                if not norm or norm in seen:
                    continue
                seen.add(norm)
                results.append({'url': norm, 'source': 'shodan', 'metadata': {'query': query}})
                if len(results) >= max_results:
                    return results
        except Exception as exc:
            logger.warning('Shodan discovery failed for %s: %s', query, exc)
    return results


async def discover_targets(sources: list[str], max_per_source: int) -> dict[str, DiscoveryTarget]:
    merged: dict[str, DiscoveryTarget] = {}

    async def add_many(items: list[dict[str, Any]]):
        for item in items:
            norm = _normalize_url(item.get('url', ''))
            if not norm:
                continue
            target = merged.setdefault(norm, DiscoveryTarget(url=norm))
            source = item.get('source', 'unknown')
            target.sources.add(source)
            meta = item.get('metadata') or {}
            target.metadata[source].append(meta)

    if 'shodan' in sources:
        await add_many(await _discover_shodan(max_per_source))
    if 'commoncrawl' in sources:
        await add_many(await commoncrawl_source.discover_targets(max_results=max_per_source))
    if 'builtwith' in sources:
        await add_many(await builtwith_source.discover_targets(max_results=max_per_source))
    return merged


async def _scan_batch(batch: list[DiscoveryTarget]) -> list[ScanResult]:
    tasks = [scan(item.url) for item in batch]
    return await asyncio.gather(*tasks, return_exceptions=False)


async def run_discovery_scan(sources: list[str], max_per_source: int, batch_size: int, findings_output: Path | None = None, inventory_output: Path | None = None):
    RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    if findings_output is None:
        findings_output = RESULTS_DIR / f'findings_{ts}.jsonl'
    if inventory_output is None:
        inventory_output = RESULTS_DIR / f'inventory_{ts}.jsonl'

    targets = await discover_targets(sources, max_per_source)
    logger.info('Discovered %d unique targets across sources: %s', len(targets), ', '.join(sources))

    scanned = 0
    found_creds = 0
    found_vuln = 0
    target_list = list(targets.values())
    for i in range(0, len(target_list), batch_size):
        batch = target_list[i:i + batch_size]
        results = await _scan_batch(batch)
        for target, result in zip(batch, results):
            scanned += 1
            if result.found_credentials:
                found_creds += 1
            if result.vulnerable_tables:
                found_vuln += 1
            record = _serialize_result(result, target)
            _append_jsonl(inventory_output, record)
            if result.vulnerable_tables:
                _append_jsonl(findings_output, record)
        logger.info('Progress: %d/%d scanned | %d with creds | %d vulnerable', scanned, len(target_list), found_creds, found_vuln)

    logger.info('Discovery scan complete. Findings: %s | Inventory: %s', findings_output, inventory_output)
    return findings_output, inventory_output


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    parser = argparse.ArgumentParser(description='Unified Supabase discovery runner')
    parser.add_argument('--sources', default='shodan,commoncrawl,builtwith', help='Comma-separated sources to run')
    parser.add_argument('--max-per-source', type=int, default=1000, help='Max targets to ingest from each source')
    parser.add_argument('--batch', type=int, default=10, help='Concurrent scans per batch')
    parser.add_argument('--output', type=Path, help='Vulnerable findings JSONL output path')
    parser.add_argument('--inventory-output', type=Path, help='All scanned targets JSONL output path')
    args = parser.parse_args()
    srcs = [s.strip() for s in args.sources.split(',') if s.strip()]
    asyncio.run(run_discovery_scan(srcs, args.max_per_source, args.batch, args.output, args.inventory_output))
