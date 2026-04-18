import gzip
import json
import logging
from io import BytesIO
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)
COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
DATA_URL = "https://data.commoncrawl.org/{}"
COMMONCRAWL_QUERY_PATTERNS = [
    "*supabase*",
    "*.supabase.co",
    "*.supabase.in",
]
EXCLUDED_HOST_SUFFIXES = (
    ".supabase.co",
    ".supabase.in",
    "supabase.co",
    "supabase.in",
    "github.com",
    "raw.githubusercontent.com",
)


def _normalize_origin(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_excluded_host(host: str) -> bool:
    host = host.lower().strip('.')
    return any(host == suffix or host.endswith(suffix) for suffix in EXCLUDED_HOST_SUFFIXES)


async def _get_recent_indexes(client: httpx.AsyncClient, count: int) -> list[str]:
    resp = await client.get(COLLINFO_URL, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    indexes = []
    for item in reversed(data):
        api = item.get('cdx-api') or item.get('id')
        if api:
            indexes.append(api.rstrip('/'))
    return indexes[:count]


async def _query_index(client: httpx.AsyncClient, index_api: str, pattern: str, limit: int) -> list[dict]:
    params = {
        'url': pattern,
        'output': 'json',
        'filter': ['=status:200', 'mime-detected:text/html'],
        'limit': str(limit),
    }
    try:
        resp = await client.get(index_api, params=params, timeout=30)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning('Common Crawl query failed for %s %s: %s', index_api, pattern, exc)
        return []

    records = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


async def _fetch_warc_body(client: httpx.AsyncClient, record: dict) -> str | None:
    filename = record.get('filename')
    offset = record.get('offset')
    length = record.get('length')
    if not filename or offset is None or length is None:
        return None

    start = int(offset)
    end = start + int(length) - 1
    headers = {'Range': f'bytes={start}-{end}'}
    try:
        resp = await client.get(DATA_URL.format(filename), headers=headers, timeout=30)
        resp.raise_for_status()
        raw = gzip.decompress(resp.content)
    except Exception:
        return None

    marker = b'\r\n\r\n'
    idx = raw.find(marker)
    if idx == -1:
        marker = b'\n\n'
        idx = raw.find(marker)
    if idx == -1:
        return None
    http_payload = raw[idx + len(marker):]
    idx2 = http_payload.find(b'\r\n\r\n')
    sep_len = 4
    if idx2 == -1:
        idx2 = http_payload.find(b'\n\n')
        sep_len = 2
    if idx2 == -1:
        return None
    body = http_payload[idx2 + sep_len:]
    return body.decode('utf-8', errors='ignore')


async def discover_targets(max_results: int = 500, recent_indexes: int = 2, per_query_limit: int = 100) -> list[dict]:
    discovered: dict[str, dict] = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        indexes = await _get_recent_indexes(client, recent_indexes)
        for index_api in indexes:
            for pattern in COMMONCRAWL_QUERY_PATTERNS:
                records = await _query_index(client, index_api, pattern, per_query_limit)
                for record in records:
                    url = record.get('url')
                    if not url:
                        continue
                    parsed = urlparse(url)
                    host = parsed.hostname or ''
                    origin = _normalize_origin(url)
                    if not origin or _is_excluded_host(host):
                        continue
                    if origin in discovered:
                        discovered[origin]['matches'] += 1
                        continue

                    body = await _fetch_warc_body(client, record)
                    if not body:
                        continue
                    lowered = body.lower()
                    if 'supabase.co' not in lowered and 'supabase.in' not in lowered:
                        continue

                    discovered[origin] = {
                        'url': origin,
                        'source': 'commoncrawl',
                        'metadata': {
                            'index': index_api,
                            'matched_url': url,
                            'pattern': pattern,
                        },
                        'matches': 1,
                    }
                    if len(discovered) >= max_results:
                        return list(discovered.values())
    return list(discovered.values())
