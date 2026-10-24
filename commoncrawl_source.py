import asyncio
import gzip
import json
import logging
import math
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)
COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
DATA_URL = "https://data.commoncrawl.org/{}"
COMMONCRAWL_QUERY_PATTERNS = [
    "*supabase*",
    "*supabase*.js",
    "*.supabase.co",
    "*.supabase.in",
    "*/storage/v1/object/public/*",
    "*/auth/v1/.well-known/jwks.json",
    "*/realtime/v1/websocket*",
    "*/socket/websocket*",
]
COMMONCRAWL_BODY_MARKERS = (
    "supabase.co",
    "supabase.in",
    "sb_publishable_",
    "sb_secret_",
    "next_public_supabase_url",
    "vite_supabase_url",
    "@supabase/supabase-js",
    "/storage/v1/object/public/",
    "/auth/v1/.well-known/jwks.json",
    "/realtime/v1/websocket",
    "/socket/websocket",
)
COMMONCRAWL_USER_AGENT = (
    "SupabaseResearchScanner/1.0 (responsible-disclosure; research.skelli.win)"
)
MAX_INDEX_PAGE_RESULTS = 100
MAX_INDEX_PAGES = 10
MAX_WARC_RECORD_SIZE = 10 * 1024 * 1024
EXCLUDED_HOST_SUFFIXES = (
    ".supabase.co",
    ".supabase.in",
    "supabase.co",
    "supabase.in",
    "github.com",
    "raw.githubusercontent.com",
)


class CommonCrawlUnavailable(RuntimeError):
    """Raised when Common Crawl cannot provide its index catalogue."""


def _normalize_origin(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_excluded_host(host: str) -> bool:
    host = host.lower().strip(".")
    return any(
        host == suffix or host.endswith(suffix) for suffix in EXCLUDED_HOST_SUFFIXES
    )


async def _get_recent_indexes(client: httpx.AsyncClient, count: int) -> list[str]:
    response = None
    for attempt in range(3):
        try:
            response = await client.get(COLLINFO_URL, timeout=20)
            response.raise_for_status()
            break
        except httpx.HTTPError:
            if attempt == 2:
                raise CommonCrawlUnavailable(
                    "Common Crawl index catalogue unavailable"
                ) from None
            await asyncio.sleep(2**attempt)
    if response is None:
        raise CommonCrawlUnavailable("Common Crawl index catalogue unavailable")
    try:
        data = response.json()
    except ValueError:
        raise CommonCrawlUnavailable(
            "Common Crawl index catalogue returned invalid JSON"
        ) from None
    if not isinstance(data, list):
        raise CommonCrawlUnavailable(
            "Common Crawl index catalogue returned an invalid payload"
        )
    indexes = []
    for item in reversed(data):
        api = item.get("cdx-api") or item.get("id")
        if api:
            indexes.append(api.rstrip("/"))
    return indexes[:count]


async def _query_index(
    client: httpx.AsyncClient, index_api: str, pattern: str, limit: int
) -> list[dict]:
    records = []
    page_size = min(MAX_INDEX_PAGE_RESULTS, max(1, limit))
    page_count = min(MAX_INDEX_PAGES, math.ceil(limit / page_size))
    for page in range(page_count):
        params = {
            "url": pattern,
            "output": "json",
            "filter": [
                "=status:200",
                "mime-detected:(?:text/html|text/javascript|application/(?:x-)?javascript)",
            ],
            "limit": str(page_size),
            "page": str(page),
        }
        response = None
        for attempt in range(3):
            try:
                response = await client.get(index_api, params=params, timeout=30)
                response.raise_for_status()
                break
            except httpx.HTTPError as exc:
                if attempt == 2:
                    logger.warning(
                        "Common Crawl query failed",
                        extra={
                            "event": "commoncrawl_query_failed",
                            "error_type": type(exc).__name__,
                        },
                    )
                    return records
                await asyncio.sleep(2**attempt)
        if response is None:
            break

        page_records = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                page_records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        records.extend(page_records)
        if len(records) >= limit or len(page_records) < page_size:
            break
        await asyncio.sleep(0.25)
    return records[:limit]


async def _fetch_warc_body(client: httpx.AsyncClient, record: dict) -> str | None:
    filename = record.get("filename")
    offset = record.get("offset")
    length = record.get("length")
    if not filename or offset is None or length is None:
        return None

    start = int(offset)
    record_length = int(length)
    if record_length < 1 or record_length > MAX_WARC_RECORD_SIZE:
        return None
    end = start + record_length - 1
    headers = {"Range": f"bytes={start}-{end}"}
    try:
        resp = await client.get(DATA_URL.format(filename), headers=headers, timeout=30)
        resp.raise_for_status()
        raw = gzip.decompress(resp.content)
    except (httpx.HTTPError, OSError, ValueError):
        return None

    marker = b"\r\n\r\n"
    idx = raw.find(marker)
    if idx == -1:
        marker = b"\n\n"
        idx = raw.find(marker)
    if idx == -1:
        return None
    http_payload = raw[idx + len(marker) :]
    idx2 = http_payload.find(b"\r\n\r\n")
    sep_len = 4
    if idx2 == -1:
        idx2 = http_payload.find(b"\n\n")
        sep_len = 2
    if idx2 == -1:
        return None
    body = http_payload[idx2 + sep_len :]
    return body.decode("utf-8", errors="ignore")


async def discover_targets(
    max_results: int = 500,
    recent_indexes: int = 2,
    per_query_limit: int | None = None,
) -> list[dict]:
    discovered: dict[str, dict] = {}
    query_limit = per_query_limit or min(max_results, 1000)
    async with httpx.AsyncClient(
        follow_redirects=True,
        headers={"User-Agent": COMMONCRAWL_USER_AGENT},
    ) as client:
        indexes = await _get_recent_indexes(client, recent_indexes)
        for index_api in indexes:
            for pattern in COMMONCRAWL_QUERY_PATTERNS:
                records = await _query_index(client, index_api, pattern, query_limit)
                for record in records:
                    url = record.get("url")
                    if not url:
                        continue
                    parsed = urlparse(url)
                    host = parsed.hostname or ""
                    origin = _normalize_origin(url)
                    if not origin or _is_excluded_host(host):
                        continue
                    if origin in discovered:
                        discovered[origin]["matches"] += 1
                        continue

                    body = await _fetch_warc_body(client, record)
                    if not body:
                        continue
                    lowered = body.lower()
                    signals = sorted(
                        marker
                        for marker in COMMONCRAWL_BODY_MARKERS
                        if marker in lowered
                    )
                    if not signals:
                        continue

                    confidence = "medium"
                    if any(
                        marker in signals
                        for marker in (
                            "sb_publishable_",
                            "sb_secret_",
                            "next_public_supabase_url",
                            "vite_supabase_url",
                        )
                    ):
                        confidence = "high"

                    discovered[origin] = {
                        "url": origin,
                        "source": "commoncrawl",
                        "metadata": {
                            "index": index_api,
                            "matched_url": url,
                            "pattern": pattern,
                            "signals": signals,
                            "confidence": confidence,
                        },
                        "matches": 1,
                    }
                    if len(discovered) >= max_results:
                        return list(discovered.values())
    return list(discovered.values())
