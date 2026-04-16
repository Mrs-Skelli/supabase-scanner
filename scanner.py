"""
Core Supabase credential and RLS scanner.
Fetches a target URL, extracts JS, finds Supabase credentials,
then probes the REST API to identify tables with RLS disabled.
"""

import re
import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Patterns
SUPABASE_URL_RE = re.compile(
    r'https?://([a-zA-Z0-9-]+)\.supabase\.co', re.IGNORECASE
)
# JWT — matches the anon key format (HS256 header)
ANON_KEY_RE = re.compile(
    r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+'
)
# Heuristic: only keep JWTs that appear near "anon" or "key" within 200 chars
ANON_KEY_CONTEXT_RE = re.compile(
    r'(?:anon|anonKey|anon_key|ANON|apikey|api_key).{0,200}?'
    r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+)',
    re.IGNORECASE | re.DOTALL,
)
# Also catch the reverse order (key before label)
ANON_KEY_CONTEXT_RE2 = re.compile(
    r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+)'
    r'.{0,200}?(?:anon|anonKey|anon_key|ANON|apikey|api_key)',
    re.IGNORECASE | re.DOTALL,
)

HEADERS = {
    "User-Agent": "SupabaseRLSScanner/1.0 (security-research; responsible-disclosure)",
}

# Hard limit on JS files to fetch per page
MAX_JS_FILES = 40
# Max JS file size to download (bytes)
MAX_JS_SIZE = 5 * 1024 * 1024  # 5 MB
# Timeout for all HTTP requests
REQUEST_TIMEOUT = 15


@dataclass
class Credential:
    supabase_url: str
    project_id: str
    anon_key: str
    source_file: str  # which JS file it came from


@dataclass
class TableResult:
    name: str
    row_count: int | None  # None = couldn't determine
    sample_columns: list[str] = field(default_factory=list)
    rls_likely_disabled: bool = False
    error: str | None = None


@dataclass
class ScanResult:
    target_url: str
    credentials: list[Credential] = field(default_factory=list)
    tables_checked: list[TableResult] = field(default_factory=list)
    js_files_scanned: int = 0
    error: str | None = None

    @property
    def found_credentials(self) -> bool:
        return len(self.credentials) > 0

    @property
    def vulnerable_tables(self) -> list[TableResult]:
        return [t for t in self.tables_checked if t.rls_likely_disabled]


async def _fetch(client: httpx.AsyncClient, url: str) -> str | None:
    """Fetch text content from a URL, return None on error."""
    try:
        resp = await client.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                                follow_redirects=True)
        if resp.status_code == 200:
            # Respect size limit
            if len(resp.content) > MAX_JS_SIZE:
                logger.warning("Skipping large file %s (%d bytes)", url, len(resp.content))
                return None
            return resp.text
    except Exception as exc:
        logger.debug("Failed to fetch %s: %s", url, exc)
    return None


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    """Return absolute URLs for all <script src="..."> tags."""
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"].strip()
        if src.startswith("data:"):
            continue
        absolute = urljoin(base_url, src)
        # Only fetch same-origin or well-known CDN scripts
        urls.append(absolute)
    return urls[:MAX_JS_FILES]


def _extract_inline_scripts(html: str) -> list[str]:
    """Return text content of all inline <script> tags."""
    soup = BeautifulSoup(html, "html.parser")
    return [
        tag.string
        for tag in soup.find_all("script", src=False)
        if tag.string
    ]


def _find_credentials(text: str, source: str) -> list[Credential]:
    """Extract Supabase URL + anon key pairs from a blob of text."""
    creds = []
    urls = SUPABASE_URL_RE.findall(text)  # returns project IDs
    if not urls:
        return creds

    # Try context-aware key extraction first
    keys = set(ANON_KEY_CONTEXT_RE.findall(text))
    keys |= set(ANON_KEY_CONTEXT_RE2.findall(text))

    # Fallback: grab all JWTs if context match found nothing
    if not keys:
        keys = set(ANON_KEY_RE.findall(text))

    for project_id in set(urls):
        supabase_url = f"https://{project_id}.supabase.co"
        for key in keys:
            creds.append(Credential(
                supabase_url=supabase_url,
                project_id=project_id,
                anon_key=key,
                source_file=source,
            ))
    return creds


async def _get_table_names(client: httpx.AsyncClient, cred: Credential) -> list[str]:
    """
    Use the Supabase OpenAPI spec to discover table names.
    GET /rest/v1/ returns an OpenAPI 2.0 spec with all table paths.
    """
    url = f"{cred.supabase_url}/rest/v1/"
    try:
        resp = await client.get(
            url,
            headers={**HEADERS, "apikey": cred.anon_key, "Authorization": f"Bearer {cred.anon_key}"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
        spec = resp.json()
        # OpenAPI 2.0: paths like /table_name
        paths = spec.get("paths", {})
        tables = [p.lstrip("/") for p in paths if p != "/" and "rpc" not in p]
        return tables
    except Exception as exc:
        logger.debug("Failed to get table list: %s", exc)
        return []


async def _check_table_rls(
    client: httpx.AsyncClient, cred: Credential, table: str
) -> TableResult:
    """
    Query a single table with only the anon key (no user JWT).
    If rows come back, RLS is likely disabled for this table.
    """
    url = f"{cred.supabase_url}/rest/v1/{table}"
    params = {"select": "*", "limit": "5"}
    headers = {
        **HEADERS,
        "apikey": cred.anon_key,
        "Authorization": f"Bearer {cred.anon_key}",
        "Accept": "application/json",
    }
    try:
        resp = await client.get(url, params=params, headers=headers,
                                timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 0:
                sample_cols = list(data[0].keys()) if data else []
                return TableResult(
                    name=table,
                    row_count=len(data),
                    sample_columns=sample_cols,
                    rls_likely_disabled=True,
                )
            # Empty list — table exists but no rows (or RLS returns empty set)
            return TableResult(name=table, row_count=0, rls_likely_disabled=False)
        elif resp.status_code in (401, 403):
            return TableResult(name=table, row_count=None, rls_likely_disabled=False)
        else:
            return TableResult(name=table, row_count=None,
                               error=f"HTTP {resp.status_code}")
    except Exception as exc:
        return TableResult(name=table, row_count=None, error=str(exc))


async def scan(target_url: str) -> ScanResult:
    """
    Full scan pipeline:
    1. Fetch target HTML
    2. Extract + fetch all JS files
    3. Find Supabase credentials
    4. Probe tables for missing RLS
    """
    result = ScanResult(target_url=target_url)

    # Normalize URL
    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "https://" + target_url
        result.target_url = target_url

    async with httpx.AsyncClient(verify=True) as client:
        # Step 1: fetch the page
        html = await _fetch(client, target_url)
        if html is None:
            result.error = "Failed to fetch target URL"
            return result

        # Step 2: collect JS sources
        js_urls = _extract_js_urls(html, target_url)
        inline_scripts = _extract_inline_scripts(html)

        # Check inline scripts first
        all_text_sources: list[tuple[str, str]] = [
            (script, "inline") for script in inline_scripts
        ]

        # Fetch external JS concurrently
        if js_urls:
            tasks = [_fetch(client, u) for u in js_urls]
            fetched = await asyncio.gather(*tasks)
            for url, content in zip(js_urls, fetched):
                if content:
                    all_text_sources.append((content, url))

        result.js_files_scanned = len(js_urls)

        # Also search the raw HTML itself (env vars sometimes land in meta tags)
        all_text_sources.append((html, target_url + " [html]"))

        # Step 3: find credentials
        seen_keys: set[str] = set()
        for text, source in all_text_sources:
            for cred in _find_credentials(text, source):
                if cred.anon_key not in seen_keys:
                    seen_keys.add(cred.anon_key)
                    result.credentials.append(cred)

        if not result.credentials:
            return result

        # Step 4: probe tables for each unique credential
        seen_projects: set[str] = set()
        for cred in result.credentials:
            if cred.project_id in seen_projects:
                continue
            seen_projects.add(cred.project_id)

            tables = await _get_table_names(client, cred)
            if not tables:
                continue

            # Check tables concurrently (but cap concurrency to be polite)
            sem = asyncio.Semaphore(5)

            async def _checked(t: str) -> TableResult:
                async with sem:
                    return await _check_table_rls(client, cred, t)

            table_results = await asyncio.gather(*[_checked(t) for t in tables])
            result.tables_checked.extend(table_results)

    return result
