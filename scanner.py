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

# --- Patterns ---
SUPABASE_URL_RE = re.compile(
    r'https?://([a-zA-Z0-9-]+)\.supabase\.co', re.IGNORECASE
)
ANON_KEY_RE = re.compile(
    r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+'
)
ANON_KEY_CONTEXT_RE = re.compile(
    r'(?:anon|anonKey|anon_key|ANON|apikey|api_key).{0,200}?'
    r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+)',
    re.IGNORECASE | re.DOTALL,
)
ANON_KEY_CONTEXT_RE2 = re.compile(
    r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+)'
    r'.{0,200}?(?:anon|anonKey|anon_key|ANON|apikey|api_key)',
    re.IGNORECASE | re.DOTALL,
)
# Extract table names from Supabase client calls: .from("table_name"), .from('table_name')
TABLE_FROM_RE = re.compile(
    r'\.from\(\s*["\x27]([a-zA-Z_][a-zA-Z0-9_]*)["\x27]\s*\)'
)
# Also catch rpc calls: .rpc("function_name")
RPC_RE = re.compile(
    r'\.rpc\(\s*["\x27]([a-zA-Z_][a-zA-Z0-9_]*)["\x27]'
)

HEADERS = {
    "User-Agent": "SupabaseRLSScanner/1.0 (security-research; responsible-disclosure)",
}

MAX_JS_FILES = 40
MAX_JS_SIZE = 5 * 1024 * 1024
REQUEST_TIMEOUT = 15

# Fallback table names when no JS extraction or OpenAPI spec
COMMON_TABLE_NAMES = [
    "users", "profiles", "accounts", "members", "customers", "clients",
    "user_profiles", "user_settings", "user_roles", "roles", "permissions",
    "posts", "articles", "pages", "comments", "messages", "notifications",
    "conversations", "threads", "replies", "channels", "servers",
    "direct_messages", "chat_messages", "rooms",
    "products", "orders", "order_items", "invoices", "payments", "subscriptions",
    "plans", "prices", "carts", "cart_items", "transactions",
    "items", "documents", "files", "uploads", "images", "media", "attachments",
    "records", "entries", "logs", "events", "analytics",
    "projects", "workspaces", "organizations", "teams", "invitations",
    "tasks", "todos", "notes", "bookmarks", "favorites", "tags", "categories",
    "settings", "configs", "options", "metadata", "features", "flags",
    "contacts", "addresses", "reviews", "ratings", "feedback",
    "sessions", "tokens", "api_keys", "webhooks",
    "employees", "departments", "reports", "daily_reports", "schedules",
    "companies", "tenants", "groups", "collections", "family_members",
]


@dataclass
class Credential:
    supabase_url: str
    project_id: str
    anon_key: str
    source_file: str


@dataclass
class TableResult:
    name: str
    row_count: int | None
    sample_columns: list[str] = field(default_factory=list)
    rls_likely_disabled: bool = False
    error: str | None = None


@dataclass
class ScanResult:
    target_url: str
    credentials: list[Credential] = field(default_factory=list)
    tables_checked: list[TableResult] = field(default_factory=list)
    js_files_scanned: int = 0
    auth_mode: str = "anon"
    error: str | None = None

    @property
    def found_credentials(self) -> bool:
        return len(self.credentials) > 0

    @property
    def vulnerable_tables(self) -> list[TableResult]:
        return [t for t in self.tables_checked if t.rls_likely_disabled]


async def _fetch(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        resp = await client.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT,
                                follow_redirects=True)
        if resp.status_code == 200:
            if len(resp.content) > MAX_JS_SIZE:
                return None
            return resp.text
    except Exception as exc:
        logger.debug("Failed to fetch %s: %s", url, exc)
    return None


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    """Extract JS URLs from <script src> and <link rel=modulepreload> tags."""
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    # Standard script tags
    for tag in soup.find_all("script", src=True):
        src = tag["src"].strip()
        if not src.startswith("data:"):
            urls.append(urljoin(base_url, src))
    # Vite/modern bundlers use <link rel="modulepreload" href="...">
    for tag in soup.find_all("link", rel=True):
        rels = tag.get("rel", [])
        if "modulepreload" in rels or ("preload" in rels and tag.get("as") == "script"):
            href = tag.get("href", "").strip()
            if href and not href.startswith("data:"):
                urls.append(urljoin(base_url, href))
    return urls[:MAX_JS_FILES]


def _extract_inline_scripts(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    return [tag.string for tag in soup.find_all("script", src=False) if tag.string]


def _extract_table_names_from_js(text: str) -> set[str]:
    """Extract table names from Supabase client .from("table") calls in JS."""
    tables = set(TABLE_FROM_RE.findall(text))
    # Filter out obvious non-table values
    skip = {"string", "object", "function", "undefined", "null", "true", "false",
            "length", "prototype", "constructor", "default", "exports", "module"}
    return {t for t in tables if t not in skip and len(t) > 1}


def _find_credentials(text: str, source: str) -> list[Credential]:
    creds = []
    urls = SUPABASE_URL_RE.findall(text)
    if not urls:
        return creds
    keys = set(ANON_KEY_CONTEXT_RE.findall(text))
    keys |= set(ANON_KEY_CONTEXT_RE2.findall(text))
    if not keys:
        keys = set(ANON_KEY_RE.findall(text))
    for project_id in set(urls):
        supabase_url = f"https://{project_id}.supabase.co"
        for key in keys:
            creds.append(Credential(
                supabase_url=supabase_url, project_id=project_id,
                anon_key=key, source_file=source,
            ))
    return creds


def _build_headers(cred: Credential, auth_token: str | None = None) -> dict:
    bearer = auth_token if auth_token else cred.anon_key
    return {
        **HEADERS,
        "apikey": cred.anon_key,
        "Authorization": f"Bearer {bearer}",
    }


async def _get_table_names_openapi(
    client: httpx.AsyncClient, cred: Credential, auth_token: str | None = None
) -> list[str] | None:
    """Try OpenAPI spec. Returns None if locked/failed."""
    url = f"{cred.supabase_url}/rest/v1/"
    headers = {**_build_headers(cred, auth_token), "Accept": "application/json"}
    try:
        resp = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            spec = resp.json()
            paths = spec.get("paths", {})
            tables = [
                p.lstrip("/") for p in paths
                if p != "/" and "rpc" not in p and "{" not in p
            ]
            if tables:
                logger.info("OpenAPI: %d tables for %s", len(tables), cred.project_id)
                return tables
    except Exception as exc:
        logger.debug("OpenAPI failed for %s: %s", cred.project_id, exc)
    return None


async def _verify_tables_exist(
    client: httpx.AsyncClient, cred: Credential,
    candidates: list[str], auth_token: str | None = None,
) -> list[str]:
    """Probe candidate table names. 404 = doesn't exist, anything else = exists."""
    sem = asyncio.Semaphore(10)

    async def _probe(name: str) -> str | None:
        async with sem:
            try:
                r = await client.get(
                    f"{cred.supabase_url}/rest/v1/{name}",
                    params={"select": "*", "limit": "0"},
                    headers={**_build_headers(cred, auth_token), "Accept": "application/json"},
                    timeout=REQUEST_TIMEOUT,
                )
                if r.status_code != 404:
                    return name
            except Exception:
                pass
            return None

    results = await asyncio.gather(*[_probe(n) for n in candidates])
    return [r for r in results if r is not None]


async def _get_table_names(
    client: httpx.AsyncClient, cred: Credential,
    js_extracted_tables: set[str], auth_token: str | None = None,
) -> list[str]:
    """
    Table discovery in order of preference:
    1. OpenAPI spec (if not locked)
    2. JS-extracted .from("table") names (verified against API)
    3. Brute-force common names (verified against API)
    """
    # Try OpenAPI first
    openapi_tables = await _get_table_names_openapi(client, cred, auth_token)
    if openapi_tables:
        return openapi_tables

    # Combine JS-extracted tables + common wordlist, deduplicated
    candidates = list(js_extracted_tables)
    # Add common names not already found in JS
    for name in COMMON_TABLE_NAMES:
        if name not in js_extracted_tables:
            candidates.append(name)

    logger.info("OpenAPI locked for %s. Probing %d candidates (%d from JS, %d common)",
                cred.project_id, len(candidates), len(js_extracted_tables),
                len(candidates) - len(js_extracted_tables))

    found = await _verify_tables_exist(client, cred, candidates, auth_token)
    logger.info("Found %d tables for %s: %s", len(found), cred.project_id, found)
    return found


def _parse_content_range(header: str | None) -> int | None:
    if not header:
        return None
    try:
        total_str = header.split("/")[-1]
        if total_str == "*":
            return None
        return int(total_str)
    except (ValueError, IndexError):
        return None


async def _check_table_rls(
    client: httpx.AsyncClient, cred: Credential, table: str,
    auth_token: str | None = None,
) -> TableResult:
    url = f"{cred.supabase_url}/rest/v1/{table}"
    params = {"select": "*", "limit": "1"}
    headers = {
        **_build_headers(cred, auth_token),
        "Accept": "application/json",
        "Prefer": "count=exact",
    }
    try:
        resp = await client.get(url, params=params, headers=headers,
                                timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            total = _parse_content_range(resp.headers.get("content-range"))
            sample_cols = list(data[0].keys()) if isinstance(data, list) and data else []

            if total is not None and total > 0:
                return TableResult(
                    name=table, row_count=total,
                    sample_columns=sample_cols, rls_likely_disabled=True,
                )
            elif isinstance(data, list) and len(data) > 0:
                return TableResult(
                    name=table, row_count=len(data),
                    sample_columns=sample_cols, rls_likely_disabled=True,
                )
            return TableResult(
                name=table, row_count=0, rls_likely_disabled=False,
                error="empty (table empty or RLS active)",
            )
        elif resp.status_code in (401, 403):
            return TableResult(name=table, row_count=None, rls_likely_disabled=False)
        else:
            return TableResult(name=table, row_count=None,
                               error=f"HTTP {resp.status_code}")
    except Exception as exc:
        return TableResult(name=table, row_count=None, error=str(exc))


async def scan(target_url: str, auth_token: str | None = None) -> ScanResult:
    result = ScanResult(
        target_url=target_url,
        auth_mode="authenticated" if auth_token else "anon",
    )

    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "https://" + target_url
        result.target_url = target_url

    async with httpx.AsyncClient(verify=True) as client:
        html = await _fetch(client, target_url)
        if html is None:
            result.error = "Failed to fetch target URL"
            return result

        js_urls = _extract_js_urls(html, target_url)
        inline_scripts = _extract_inline_scripts(html)

        all_text_sources: list[tuple[str, str]] = [
            (script, "inline") for script in inline_scripts
        ]

        if js_urls:
            tasks = [_fetch(client, u) for u in js_urls]
            fetched = await asyncio.gather(*tasks)
            for url, content in zip(js_urls, fetched):
                if content:
                    all_text_sources.append((content, url))

        result.js_files_scanned = len(js_urls)
        all_text_sources.append((html, target_url + " [html]"))

        # Extract credentials AND table names from all JS sources
        seen_keys: set[str] = set()
        js_tables: set[str] = set()
        for text, source in all_text_sources:
            for cred in _find_credentials(text, source):
                if cred.anon_key not in seen_keys:
                    seen_keys.add(cred.anon_key)
                    result.credentials.append(cred)
            js_tables |= _extract_table_names_from_js(text)

        if js_tables:
            logger.info("Extracted %d table names from JS: %s", len(js_tables), js_tables)

        if not result.credentials:
            return result

        # Probe tables for each unique credential
        seen_projects: set[str] = set()
        for cred in result.credentials:
            if cred.project_id in seen_projects:
                continue
            seen_projects.add(cred.project_id)

            tables = await _get_table_names(client, cred, js_tables, auth_token)
            if not tables:
                continue

            sem = asyncio.Semaphore(5)

            async def _checked(t: str) -> TableResult:
                async with sem:
                    return await _check_table_rls(client, cred, t, auth_token)

            table_results = await asyncio.gather(*[_checked(t) for t in tables])
            result.tables_checked.extend(table_results)

    return result
