"""
Core Supabase client-configuration and access scanner.
Fetches a target URL, extracts JavaScript, finds Supabase configuration,
then probes the REST API for tables that return rows in the selected mode.
"""

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ssrf_guard import MAX_REDIRECTS, validate_url

logger = logging.getLogger(__name__)

# --- Patterns ---
_LEGACY_PUBLIC_KEY = (
    r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\."
    r"[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+"
)
_PUBLISHABLE_KEY = r"sb_publishable_[A-Za-z0-9_-]{20,}"
_SECRET_KEY = r"sb_secret_[A-Za-z0-9_-]{20,}"
_PUBLIC_KEY = rf"(?:{_LEGACY_PUBLIC_KEY}|{_PUBLISHABLE_KEY})"

SUPABASE_URL_RE = re.compile(
    r"https?://[a-zA-Z0-9-]+\.supabase\.(?:co|in)(?:/[^\s\"']*)?",
    re.IGNORECASE,
)
PUBLIC_KEY_RE = re.compile(_PUBLIC_KEY)
SECRET_KEY_RE = re.compile(_SECRET_KEY)
CREATE_CLIENT_RE = re.compile(
    rf"createClient\s*\(\s*[\"'](?P<url>https?://[^\"']+)[\"']\s*,\s*"
    rf"[\"'](?P<key>{_PUBLIC_KEY}|{_SECRET_KEY})[\"']",
    re.IGNORECASE,
)
SUPABASE_URL_CONFIG_RE = re.compile(
    r"(?<![A-Za-z0-9_])[\"']?"
    r"(?:(?:(?:NEXT_PUBLIC|VITE|PUBLIC)_)?SUPABASE_URL|supabase[_-]?url)"
    r"[\"']?\s*[:=]\s*[\"']"
    r"(?P<url>https?://[^\"']+)[\"']",
    re.IGNORECASE,
)
SUPABASE_KEY_CONFIG_RE = re.compile(
    rf"(?<![A-Za-z0-9_])[\"']?"
    rf"(?:(?:(?:NEXT_PUBLIC|VITE|PUBLIC)_)?SUPABASE_"
    rf"(?:(?:ANON|PUBLISHABLE|SECRET|SERVICE_ROLE)_)?KEY|"
    rf"supabase[_-]?(?:(?:anon|publishable|secret|service[_-]?role)[_-]?)?key|"
    rf"anon[_-]?key)"
    rf"[\"']?"
    rf"\s*[:=]\s*[\"'](?P<key>{_PUBLIC_KEY}|{_SECRET_KEY})[\"']",
    re.IGNORECASE,
)
SUPABASE_SERVICE_URL_RE = re.compile(
    r"(?P<url>(?:https?|wss?)://[A-Za-z0-9._:-]+"
    r"/(?:"
    r"(?:rest|auth|storage|realtime|functions)/v1(?:/[^\s\"'<>]*)?"
    r"|graphql/v1(?:[^\s\"'<>]*)?"
    r"|socket/websocket(?:[^\s\"'<>]*)?"
    r"))",
    re.IGNORECASE,
)
MAX_CONFIG_PAIR_DISTANCE = 500
MAX_SERVICE_PAIR_DISTANCE = 1500
# Extract table names from Supabase client calls such as .from("table_name").
TABLE_FROM_RE = re.compile(r'\.from\(\s*["\x27]([a-zA-Z_][a-zA-Z0-9_]*)["\x27]\s*\)')
# Also catch rpc calls: .rpc("function_name")
RPC_RE = re.compile(r'\.rpc\(\s*["\x27]([a-zA-Z_][a-zA-Z0-9_]*)["\x27]')

HEADERS = {
    "User-Agent": "SupabaseRLSScanner/1.0 (security-research; responsible-disclosure)",
}

MAX_JS_FILES = 40
MAX_JS_SIZE = 5 * 1024 * 1024
REQUEST_TIMEOUT = 15

# Fallback table names when no JS extraction or OpenAPI spec
COMMON_TABLE_NAMES = [
    "users",
    "profiles",
    "accounts",
    "members",
    "customers",
    "clients",
    "user_profiles",
    "user_settings",
    "user_roles",
    "roles",
    "permissions",
    "posts",
    "articles",
    "pages",
    "comments",
    "messages",
    "notifications",
    "conversations",
    "threads",
    "replies",
    "channels",
    "servers",
    "direct_messages",
    "chat_messages",
    "rooms",
    "products",
    "orders",
    "order_items",
    "invoices",
    "payments",
    "subscriptions",
    "plans",
    "prices",
    "carts",
    "cart_items",
    "transactions",
    "items",
    "documents",
    "files",
    "uploads",
    "images",
    "media",
    "attachments",
    "records",
    "entries",
    "logs",
    "events",
    "analytics",
    "projects",
    "workspaces",
    "organizations",
    "teams",
    "invitations",
    "tasks",
    "todos",
    "notes",
    "bookmarks",
    "favorites",
    "tags",
    "categories",
    "settings",
    "configs",
    "options",
    "metadata",
    "features",
    "flags",
    "contacts",
    "addresses",
    "reviews",
    "ratings",
    "feedback",
    "sessions",
    "tokens",
    "api_keys",
    "webhooks",
    "employees",
    "departments",
    "reports",
    "daily_reports",
    "schedules",
    "companies",
    "tenants",
    "groups",
    "collections",
    "family_members",
]


@dataclass
class Credential:
    supabase_url: str
    project_id: str
    anon_key: str
    source_file: str


@dataclass
class TableResult:
    """Result of checking a single table with the selected credentials."""

    name: str
    row_count: int | None
    sample_columns: list[str] = field(default_factory=list)
    rls_likely_disabled: bool = False
    error: str | None = None
    sample_data: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class SensitiveKeyExposure:
    """Non-reusable metadata for privileged key material found client-side."""

    key_type: str
    occurrence_count: int
    source_file: str
    fingerprint: str


@dataclass
class ScanResult:
    target_url: str
    credentials: list[Credential] = field(default_factory=list)
    sensitive_key_exposures: list[SensitiveKeyExposure] = field(default_factory=list)
    tables_checked: list[TableResult] = field(default_factory=list)
    js_files_scanned: int = 0
    auth_mode: str = "anon"
    error: str | None = None

    @property
    def found_credentials(self) -> bool:
        return bool(self.credentials)

    @property
    def vulnerable_tables(self) -> list[TableResult]:
        """Compatibility alias for tables that returned rows."""
        return [t for t in self.tables_checked if t.rls_likely_disabled]

    @property
    def has_reportable_findings(self) -> bool:
        """Return whether the result contains independently reportable evidence."""
        return bool(self.vulnerable_tables or self.sensitive_key_exposures)


def _source_label(url: str) -> str:
    """Return a URL label without query parameters, fragments, or userinfo."""
    try:
        parsed = urlparse(url)
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return "[invalid-url]"
    if not parsed.hostname:
        return "[invalid-url]"
    return f"{parsed.scheme}://{parsed.hostname}{port}{parsed.path}"


async def _fetch(
    client: httpx.AsyncClient, url: str, *, _ssrf_check: bool = True
) -> str | None:
    if _ssrf_check:
        err = validate_url(url)
        if err:
            logger.warning("SSRF blocked request", extra={"event": "ssrf_blocked"})
            return None
    try:
        # Manual redirect following with SSRF validation on each hop
        current_url = url
        for _ in range(MAX_REDIRECTS):
            resp = await client.get(
                current_url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    return None
                current_url = urljoin(current_url, location)
                err = validate_url(current_url)
                if err:
                    logger.warning(
                        "SSRF blocked redirect",
                        extra={"event": "ssrf_redirect_blocked"},
                    )
                    return None
                continue
            if resp.status_code in (200, 206):
                if len(resp.content) > MAX_JS_SIZE:
                    return None
                return resp.text
            return None
        logger.debug("Too many redirects", extra={"event": "redirect_limit"})
        return None
    except httpx.HTTPError as exc:
        logger.debug(
            "Fetch failed",
            extra={"event": "fetch_failed", "error_type": type(exc).__name__},
        )
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
    skip = {
        "string",
        "object",
        "function",
        "undefined",
        "null",
        "true",
        "false",
        "length",
        "prototype",
        "constructor",
        "default",
        "exports",
        "module",
    }
    return {t for t in tables if t not in skip and len(t) > 1}


def _normalize_supabase_url(value: str) -> str | None:
    """Normalize a strongly paired Supabase URL before active use."""
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    normalized = parsed._replace(query="", fragment="").geturl().rstrip("/")
    if validate_url(normalized):
        return None
    return normalized


def _origin_from_service_url(value: str) -> str | None:
    """Return an HTTP API origin from a documented Supabase service URL."""
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
        return None
    scheme = (
        "https"
        if parsed.scheme == "wss"
        else "http"
        if parsed.scheme == "ws"
        else parsed.scheme
    )
    return f"{scheme}://{parsed.netloc}"


def _project_id_for_url(supabase_url: str) -> str:
    hostname = urlparse(supabase_url).hostname or "unknown"
    hosted_suffix = ".supabase.co"
    if hostname.lower().endswith(hosted_suffix):
        return hostname[: -len(hosted_suffix)]
    return hostname


def _legacy_jwt_role(key: str) -> str | None:
    """Read a legacy JWT role only to exclude privileged browser leaks."""
    try:
        payload = key.split(".", maxsplit=2)[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (
        binascii.Error,
        IndexError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None
    if not isinstance(claims, dict):
        return None
    role = claims.get("role")
    return role if isinstance(role, str) else None


def _is_public_client_key(key: str) -> bool:
    if SECRET_KEY_RE.fullmatch(key):
        return False
    if key.startswith("sb_publishable_"):
        return bool(PUBLIC_KEY_RE.fullmatch(key))
    if not PUBLIC_KEY_RE.fullmatch(key):
        return False
    return _legacy_jwt_role(key) == "anon"


def _key_fingerprint(value: str) -> str:
    """Return a short correlation fingerprint that cannot recover the key."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _sensitive_key_exposures(text: str, source: str) -> list[SensitiveKeyExposure]:
    detected: Counter[tuple[str, str]] = Counter()
    for value in SECRET_KEY_RE.findall(text):
        detected[("sb_secret", _key_fingerprint(value))] += 1
    for value in PUBLIC_KEY_RE.findall(text):
        role = _legacy_jwt_role(value)
        if role in {"service_role", "supabase_admin"}:
            detected[(f"legacy_{role}", _key_fingerprint(value))] += 1
    return [
        SensitiveKeyExposure(
            key_type=key_type,
            occurrence_count=count,
            source_file=source,
            fingerprint=fingerprint,
        )
        for (key_type, fingerprint), count in sorted(detected.items())
    ]


def _coalesce_sensitive_key_exposures(
    exposures: list[SensitiveKeyExposure],
) -> list[SensitiveKeyExposure]:
    totals: Counter[tuple[str, str, str]] = Counter()
    for exposure in exposures:
        totals[(exposure.key_type, exposure.fingerprint, exposure.source_file)] += (
            exposure.occurrence_count
        )
    return [
        SensitiveKeyExposure(
            key_type=key_type,
            occurrence_count=count,
            source_file=source_file,
            fingerprint=fingerprint,
        )
        for (key_type, fingerprint, source_file), count in sorted(totals.items())
    ]


def _credential_from_pair(url: str, key: str, source: str) -> Credential | None:
    """Build a credential only from a public client key and a safe URL."""
    if not _is_public_client_key(key):
        return None
    supabase_url = _normalize_supabase_url(url)
    if not supabase_url:
        return None
    return Credential(
        supabase_url=supabase_url,
        project_id=_project_id_for_url(supabase_url),
        anon_key=key,
        source_file=source,
    )


def _find_client_config(
    text: str, source: str
) -> tuple[list[Credential], list[SensitiveKeyExposure]]:
    pairs: set[tuple[str, str]] = set()
    exposures = _sensitive_key_exposures(text, source)

    # createClient(url, key) is the strongest signal and supports custom or
    # self-hosted deployments without treating arbitrary URLs as Supabase.
    for match in CREATE_CLIENT_RE.finditer(text):
        pairs.add((match.group("url"), match.group("key")))

    # Configuration assignments are also accepted when the named URL and key
    # appear close together in the same source file.
    url_configs = list(SUPABASE_URL_CONFIG_RE.finditer(text))
    key_configs = list(SUPABASE_KEY_CONFIG_RE.finditer(text))
    for url_match in url_configs:
        for key_match in key_configs:
            if abs(url_match.start() - key_match.start()) <= MAX_CONFIG_PAIR_DISTANCE:
                pairs.add((url_match.group("url"), key_match.group("key")))

    # Documented Supabase service URLs survive bundling even when createClient()
    # does not. Pair only a nearby public/secret key with the service origin so
    # arbitrary REST or WebSocket URLs are never treated as Supabase by themselves.
    service_urls = list(SUPABASE_SERVICE_URL_RE.finditer(text))
    key_matches = list(PUBLIC_KEY_RE.finditer(text)) + list(
        SECRET_KEY_RE.finditer(text)
    )
    for service_match in service_urls:
        origin = _origin_from_service_url(service_match.group("url"))
        if not origin:
            continue
        for key_match in key_matches:
            if (
                abs(service_match.start() - key_match.start())
                <= MAX_SERVICE_PAIR_DISTANCE
            ):
                pairs.add((origin, key_match.group(0)))

    # Hosted project URLs are independently distinctive. Preserve the legacy
    # same-file pairing behavior for bundles that inline URL and key separately.
    hosted_urls = set(SUPABASE_URL_RE.findall(text))
    public_keys = set(PUBLIC_KEY_RE.findall(text))
    pairs.update((url, key) for url in hosted_urls for key in public_keys)

    credentials = []
    for url, key in sorted(pairs):
        credential = _credential_from_pair(url, key, source)
        if credential:
            credentials.append(credential)
    return credentials, exposures


def _find_credentials(text: str, source: str) -> list[Credential]:
    """Compatibility wrapper returning only safe public client credentials."""
    credentials, _ = _find_client_config(text, source)
    return credentials


def _build_headers(cred: Credential, auth_token: str | None = None) -> dict:
    headers = {
        **HEADERS,
        "apikey": cred.anon_key,
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif _legacy_jwt_role(cred.anon_key) == "anon":
        headers["Authorization"] = f"Bearer {cred.anon_key}"
    return headers


async def _get_table_names_openapi(
    client: httpx.AsyncClient, cred: Credential, auth_token: str | None = None
) -> list[str] | None:
    """Try OpenAPI spec. Returns None if locked/failed."""
    url = f"{cred.supabase_url}/rest/v1/"
    headers = {**_build_headers(cred, auth_token), "Accept": "application/json"}
    try:
        resp = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code in (200, 206):
            spec = resp.json()
            paths = spec.get("paths", {})
            tables = [
                p.lstrip("/")
                for p in paths
                if p != "/" and "rpc" not in p and "{" not in p
            ]
            if tables:
                logger.info(
                    "OpenAPI table discovery completed",
                    extra={"event": "openapi_tables", "tables": len(tables)},
                )
                return tables
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug(
            "OpenAPI discovery failed",
            extra={"event": "openapi_failed", "error_type": type(exc).__name__},
        )
    return None


async def _get_table_names_graphql(
    client: httpx.AsyncClient, cred: Credential, auth_token: str | None = None
) -> list[str] | None:
    """
    Try GraphQL introspection at /graphql/v1.
    Supabase exposes a GraphQL endpoint that often has introspection enabled.
    Query type fields are named like employeesCollection — strip "Collection" suffix.
    """
    url = f"{cred.supabase_url}/graphql/v1"
    headers = {
        **_build_headers(cred, auth_token),
        "Content-Type": "application/json",
    }
    query = '{"query":"{ __schema { queryType { fields { name } } } }"}'
    try:
        resp = await client.post(
            url, headers=headers, content=query, timeout=REQUEST_TIMEOUT
        )
        if resp.status_code not in (200, 206):
            return None
        data = resp.json()
        fields = (
            data.get("data", {})
            .get("__schema", {})
            .get("queryType", {})
            .get("fields", [])
        )
        tables: list[str] = []
        for f in fields:
            name = f.get("name", "")
            # Supabase GraphQL names collections as "tableNameCollection"
            if name.endswith("Collection"):
                table = name[: -len("Collection")]
                tables.append(table)
        if tables:
            logger.info(
                "GraphQL table discovery completed",
                extra={"event": "graphql_tables", "tables": len(tables)},
            )
            return tables
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug(
            "GraphQL introspection failed",
            extra={"event": "graphql_failed", "error_type": type(exc).__name__},
        )
    return None


async def _verify_tables_exist(
    client: httpx.AsyncClient,
    cred: Credential,
    candidates: list[str],
    auth_token: str | None = None,
) -> list[str]:
    """Probe candidate table names. 404 = doesn't exist, anything else = exists."""
    sem = asyncio.Semaphore(10)

    async def _probe(name: str) -> str | None:
        async with sem:
            try:
                r = await client.get(
                    f"{cred.supabase_url}/rest/v1/{name}",
                    params={"select": "*", "limit": "0"},
                    headers={
                        **_build_headers(cred, auth_token),
                        "Accept": "application/json",
                    },
                    timeout=REQUEST_TIMEOUT,
                )
                # Only 200/206 confirms a table exists
                # 401/403 = can't tell (invalid key or RLS), 404 = doesn't exist
                if r.status_code in (200, 206):
                    return name
            except httpx.HTTPError as exc:
                logger.debug(
                    "Table probe failed",
                    extra={
                        "event": "table_probe_failed",
                        "error_type": type(exc).__name__,
                    },
                )
            return None

    results = await asyncio.gather(*[_probe(n) for n in candidates])
    return [r for r in results if r is not None]


async def _get_table_names(
    client: httpx.AsyncClient,
    cred: Credential,
    js_extracted_tables: set[str],
    auth_token: str | None = None,
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

    # Try GraphQL introspection
    graphql_tables = await _get_table_names_graphql(client, cred, auth_token)
    if graphql_tables:
        return graphql_tables

    # Fallback: combine JS-extracted tables + common wordlist, deduplicated
    candidates = list(js_extracted_tables)
    # Add common names not already found in JS
    for name in COMMON_TABLE_NAMES:
        if name not in js_extracted_tables:
            candidates.append(name)

    logger.info(
        "Discovery schemas locked; probing table candidates",
        extra={
            "event": "table_probe_started",
            "candidates": len(candidates),
            "js_candidates": len(js_extracted_tables),
            "common_candidates": len(candidates) - len(js_extracted_tables),
        },
    )

    found = await _verify_tables_exist(client, cred, candidates, auth_token)
    logger.info(
        "Table probe completed",
        extra={"event": "table_probe_completed", "tables": len(found)},
    )
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
    client: httpx.AsyncClient,
    cred: Credential,
    table: str,
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
        resp = await client.get(
            url, params=params, headers=headers, timeout=REQUEST_TIMEOUT
        )
        if resp.status_code in (200, 206):
            data = resp.json()
            total = _parse_content_range(resp.headers.get("content-range"))
            sample_cols = (
                list(data[0].keys()) if isinstance(data, list) and data else []
            )

            if total is not None and total > 0:
                return TableResult(
                    name=table,
                    row_count=total,
                    sample_columns=sample_cols,
                    rls_likely_disabled=True,
                    sample_data=data if isinstance(data, list) else [],
                )
            if isinstance(data, list) and data:
                return TableResult(
                    name=table,
                    row_count=len(data),
                    sample_columns=sample_cols,
                    rls_likely_disabled=True,
                    sample_data=data,
                )
            return TableResult(
                name=table,
                row_count=0,
                rls_likely_disabled=False,
                error="empty (table empty or RLS active)",
            )
        if resp.status_code in (401, 403):
            return TableResult(name=table, row_count=None, rls_likely_disabled=False)
        return TableResult(
            name=table,
            row_count=None,
            error=f"HTTP {resp.status_code}",
        )
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug(
            "Table check failed",
            extra={"event": "table_check_failed", "error_type": type(exc).__name__},
        )
        return TableResult(
            name=table,
            row_count=None,
            error=f"request failed ({type(exc).__name__})",
        )


async def _check_tables(
    client: httpx.AsyncClient,
    credential: Credential,
    tables: list[str],
    auth_token: str | None,
) -> list[TableResult]:
    """Check a project's tables with bounded per-project concurrency."""
    semaphore = asyncio.Semaphore(5)

    async def check_one(table: str) -> TableResult:
        async with semaphore:
            return await _check_table_rls(client, credential, table, auth_token)

    return await asyncio.gather(*(check_one(table) for table in tables))


async def _refresh_auth_token(
    client: httpx.AsyncClient, cred: Credential, refresh_token: str
) -> str | None:
    """Use a Supabase refresh token to get a fresh access_token."""
    url = f"{cred.supabase_url}/auth/v1/token?grant_type=refresh_token"
    try:
        resp = await client.post(
            url,
            headers={"apikey": cred.anon_key, "Content-Type": "application/json"},
            json={"refresh_token": refresh_token},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code in (200, 206):
            data = resp.json()
            token = data.get("access_token")
            if token:
                logger.info("Refreshed auth token successfully")
                return token
        logger.debug("Token refresh failed with HTTP %d", resp.status_code)
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug(
            "Token refresh error",
            extra={"event": "token_refresh_failed", "error_type": type(exc).__name__},
        )
    return None


async def scan(
    target_url: str, auth_token: str | None = None, refresh_token: str | None = None
) -> ScanResult:
    result = ScanResult(
        target_url=target_url,
        auth_mode="authenticated" if auth_token else "anon",
    )

    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "https://" + target_url
        result.target_url = target_url

    # SSRF guard: validate target URL before any server-side requests
    url_err = validate_url(target_url)
    if url_err:
        result.error = f"Blocked: {url_err}"
        return result

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
            for url, content in zip(js_urls, fetched, strict=True):
                if content:
                    all_text_sources.append((content, _source_label(url)))

        result.js_files_scanned = len(js_urls)
        all_text_sources.append((html, _source_label(target_url) + " [html]"))

        # Extract credentials AND table names from all JS sources
        seen_credentials: set[tuple[str, str]] = set()
        detected_exposures: list[SensitiveKeyExposure] = []
        js_tables: set[str] = set()
        for text, source in all_text_sources:
            credentials, exposures = _find_client_config(text, source)
            for cred in credentials:
                identity = (cred.project_id, cred.anon_key)
                if identity not in seen_credentials:
                    seen_credentials.add(identity)
                    result.credentials.append(cred)
            for exposure in exposures:
                detected_exposures.append(exposure)
            js_tables |= _extract_table_names_from_js(text)
        result.sensitive_key_exposures = _coalesce_sensitive_key_exposures(
            detected_exposures
        )

        if js_tables:
            logger.info(
                "Extracted table names from JavaScript",
                extra={"event": "js_tables_extracted", "tables": len(js_tables)},
            )

        if not result.credentials:
            return result

        # If we have a refresh_token and credentials, try to get a fresh access_token
        if refresh_token and result.credentials and auth_token:
            cred = result.credentials[0]
            fresh = await _refresh_auth_token(client, cred, refresh_token)
            if fresh:
                auth_token = fresh
                logger.info("Using refreshed auth token for RLS checks")

        # Probe tables for each unique credential
        seen_projects: set[str] = set()
        for cred in result.credentials:
            if cred.project_id in seen_projects:
                continue
            seen_projects.add(cred.project_id)

            # Always use anon key for discovery; auth_token only for RLS check
            tables = await _get_table_names(client, cred, js_tables, None)
            if not tables:
                continue

            table_results = await _check_tables(client, cred, tables, auth_token)
            result.tables_checked.extend(table_results)

    return result
