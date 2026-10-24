"""Passive Supabase candidate discovery from existing public URLScan scans."""

import asyncio
import logging
import os
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
URLSCAN_QUERIES = (
    ("hosted_supabase_co", "domain:supabase.co AND NOT page.domain:supabase.co"),
    ("hosted_supabase_in", "domain:supabase.in AND NOT page.domain:supabase.in"),
    ("rest_route", 'filename:"rest/v1"'),
    ("realtime_route", 'filename:"realtime/v1"'),
    ("storage_route", 'filename:"storage/v1"'),
    ("auth_route", 'filename:"auth/v1"'),
)
URLSCAN_PAGE_SIZE = 1000
URLSCAN_MAX_QUERY_RESULTS = 10000
URLSCAN_MAX_PAGES = 20
URLSCAN_USER_AGENT = (
    "SupabaseResearchScanner/1.0 (responsible-disclosure; research.skelli.win)"
)
EXCLUDED_HOST_SUFFIXES = (
    "supabase.co",
    "supabase.in",
    "urlscan.io",
)


class URLScanUnavailable(RuntimeError):
    """Raised when every URLScan query exhausts its retry budget."""


def _normalize_origin(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = urlparse(value)
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return f"{parsed.scheme}://{parsed.hostname.lower()}{port}"


def _is_excluded_host(origin: str) -> bool:
    host = (urlparse(origin).hostname or "").lower().strip(".")
    return any(
        host == suffix or host.endswith(f".{suffix}")
        for suffix in EXCLUDED_HOST_SUFFIXES
    )


def _search_after_value(result: dict) -> str | None:
    value = result.get("sort")
    if isinstance(value, list) and value:
        return ",".join(str(item) for item in value)
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


async def _search_page(
    client: httpx.AsyncClient,
    query: str,
    size: int,
    search_after: str | None,
) -> dict:
    params = {"q": query, "size": str(size)}
    if search_after:
        params["search_after"] = search_after
    for attempt in range(3):
        try:
            response = await client.get(URLSCAN_SEARCH_URL, params=params, timeout=30)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(
                payload.get("results", []), list
            ):
                raise URLScanUnavailable("URLScan returned an invalid payload")
            return payload
        except (httpx.HTTPError, ValueError) as exc:
            if attempt == 2:
                logger.warning(
                    "URLScan search failed",
                    extra={
                        "event": "urlscan_search_failed",
                        "error_type": type(exc).__name__,
                    },
                )
                raise URLScanUnavailable("URLScan search unavailable") from None
            await asyncio.sleep(2**attempt)
    raise RuntimeError("unreachable retry state")


async def discover_targets(
    max_results: int = 500,
    per_query_limit: int | None = None,
) -> list[dict]:
    """Return unique page origins from scans that contacted Supabase services."""
    if max_results < 1:
        raise ValueError("max_results must be at least 1")

    headers = {"User-Agent": URLSCAN_USER_AGENT}
    if api_key := os.getenv("URLSCAN_API_KEY"):
        headers["api-key"] = api_key

    query_limit = per_query_limit or max(1, max_results // len(URLSCAN_QUERIES))
    query_limit = min(query_limit, URLSCAN_MAX_QUERY_RESULTS)
    discovered: dict[str, dict] = {}
    successful_queries = 0
    failed_queries = 0

    async with httpx.AsyncClient(follow_redirects=True, headers=headers) as client:
        for signal, query in URLSCAN_QUERIES:
            search_after = None
            collected = 0
            for _page in range(URLSCAN_MAX_PAGES):
                size = min(URLSCAN_PAGE_SIZE, query_limit - collected)
                if size < 1:
                    break
                try:
                    payload = await _search_page(
                        client,
                        query,
                        size,
                        search_after,
                    )
                    successful_queries += 1
                except URLScanUnavailable:
                    failed_queries += 1
                    break

                results = payload.get("results", [])
                for item in results:
                    if not isinstance(item, dict):
                        continue
                    task = item.get("task") or {}
                    page = item.get("page") or {}
                    value = task.get("url") or page.get("url")
                    origin = _normalize_origin(value)
                    if not origin or _is_excluded_host(origin):
                        continue

                    record = discovered.setdefault(
                        origin,
                        {
                            "url": origin,
                            "source": "urlscan",
                            "metadata": {
                                "signals": [],
                                "confidence": "medium",
                            },
                            "matches": 0,
                        },
                    )
                    if signal not in record["metadata"]["signals"]:
                        record["metadata"]["signals"].append(signal)
                    record["matches"] += 1
                    if len(discovered) >= max_results:
                        return list(discovered.values())

                collected += len(results)
                if (
                    not results
                    or collected >= query_limit
                    or not payload.get("has_more")
                ):
                    break
                search_after = _search_after_value(results[-1])
                if not search_after:
                    break
                await asyncio.sleep(0.25)

    if failed_queries and not successful_queries:
        raise URLScanUnavailable("all URLScan searches failed")
    return list(discovered.values())
