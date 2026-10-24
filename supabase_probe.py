"""Bounded Supabase API discovery and read checks."""

import asyncio
import logging

import httpx

from fingerprints import legacy_jwt_role
from scan_models import Credential, TableResult

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15
HEADERS = {
    "User-Agent": "SupabaseRLSScanner/1.0 (security-research; responsible-disclosure)",
}

COMMON_TABLE_NAMES = (
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
)


def build_headers(cred: Credential, auth_token: str | None = None) -> dict[str, str]:
    """Build request headers without treating publishable keys as bearer tokens."""
    headers = {**HEADERS, "apikey": cred.anon_key}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif legacy_jwt_role(cred.anon_key) == "anon":
        headers["Authorization"] = f"Bearer {cred.anon_key}"
    return headers


async def get_table_names_openapi(
    client: httpx.AsyncClient,
    cred: Credential,
    auth_token: str | None = None,
) -> list[str] | None:
    url = f"{cred.supabase_url}/rest/v1/"
    headers = {**build_headers(cred, auth_token), "Accept": "application/json"}
    try:
        response = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code not in (200, 206):
            return None
        spec = response.json()
        paths = spec.get("paths", {})
        tables = [
            path.lstrip("/")
            for path in paths
            if path != "/" and "rpc" not in path and "{" not in path
        ]
        if tables:
            logger.info(
                "OpenAPI table discovery completed",
                extra={"event": "openapi_tables", "tables": len(tables)},
            )
            return tables
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        logger.debug(
            "OpenAPI discovery failed",
            extra={"event": "openapi_failed", "error_type": type(exc).__name__},
        )
    return None


async def get_table_names_graphql(
    client: httpx.AsyncClient,
    cred: Credential,
    auth_token: str | None = None,
) -> list[str] | None:
    url = f"{cred.supabase_url}/graphql/v1"
    headers = {
        **build_headers(cred, auth_token),
        "Content-Type": "application/json",
    }
    query = '{"query":"{ __schema { queryType { fields { name } } } }"}'
    try:
        response = await client.post(
            url, headers=headers, content=query, timeout=REQUEST_TIMEOUT
        )
        if response.status_code not in (200, 206):
            return None
        fields = (
            response.json()
            .get("data", {})
            .get("__schema", {})
            .get("queryType", {})
            .get("fields", [])
        )
        tables = [
            field["name"][: -len("Collection")]
            for field in fields
            if isinstance(field, dict)
            and isinstance(field.get("name"), str)
            and field["name"].endswith("Collection")
        ]
        if tables:
            logger.info(
                "GraphQL table discovery completed",
                extra={"event": "graphql_tables", "tables": len(tables)},
            )
            return tables
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        logger.debug(
            "GraphQL introspection failed",
            extra={"event": "graphql_failed", "error_type": type(exc).__name__},
        )
    return None


async def verify_tables_exist(
    client: httpx.AsyncClient,
    cred: Credential,
    candidates: list[str],
    auth_token: str | None = None,
) -> list[str]:
    """Return only candidate names confirmed by a successful empty read."""
    semaphore = asyncio.Semaphore(10)

    async def probe(name: str) -> str | None:
        async with semaphore:
            try:
                response = await client.get(
                    f"{cred.supabase_url}/rest/v1/{name}",
                    params={"select": "*", "limit": "0"},
                    headers={
                        **build_headers(cred, auth_token),
                        "Accept": "application/json",
                    },
                    timeout=REQUEST_TIMEOUT,
                )
                return name if response.status_code in (200, 206) else None
            except httpx.HTTPError as exc:
                logger.debug(
                    "Table probe failed",
                    extra={
                        "event": "table_probe_failed",
                        "error_type": type(exc).__name__,
                    },
                )
                return None

    results = await asyncio.gather(*(probe(name) for name in candidates))
    return [name for name in results if name is not None]


async def discover_table_names(
    client: httpx.AsyncClient,
    cred: Credential,
    js_extracted_tables: set[str],
    auth_token: str | None = None,
) -> list[str]:
    """Discover table names with schemas first, then bounded candidates."""
    openapi_tables = await get_table_names_openapi(client, cred, auth_token)
    if openapi_tables:
        return openapi_tables

    graphql_tables = await get_table_names_graphql(client, cred, auth_token)
    if graphql_tables:
        return graphql_tables

    candidates = [*sorted(js_extracted_tables)]
    candidates.extend(
        name for name in COMMON_TABLE_NAMES if name not in js_extracted_tables
    )
    logger.info(
        "Discovery schemas locked; probing table candidates",
        extra={
            "event": "table_probe_started",
            "candidates": len(candidates),
            "js_candidates": len(js_extracted_tables),
            "common_candidates": len(candidates) - len(js_extracted_tables),
        },
    )
    found = await verify_tables_exist(client, cred, candidates, auth_token)
    logger.info(
        "Table probe completed",
        extra={"event": "table_probe_completed", "tables": len(found)},
    )
    return found


def parse_content_range(header: str | None) -> int | None:
    if not header:
        return None
    try:
        total = header.rsplit("/", maxsplit=1)[-1]
        return None if total == "*" else int(total)
    except (ValueError, IndexError):
        return None


async def check_table_access(
    client: httpx.AsyncClient,
    cred: Credential,
    table: str,
    auth_token: str | None = None,
) -> TableResult:
    """Perform one bounded row read and retain at most the returned single row."""
    try:
        response = await client.get(
            f"{cred.supabase_url}/rest/v1/{table}",
            params={"select": "*", "limit": "1"},
            headers={
                **build_headers(cred, auth_token),
                "Accept": "application/json",
                "Prefer": "count=exact",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (200, 206):
            data = response.json()
            rows = data if isinstance(data, list) else []
            total = parse_content_range(response.headers.get("content-range"))
            sample_columns = list(rows[0].keys()) if rows else []
            if total is not None and total > 0:
                return TableResult(
                    name=table,
                    row_count=total,
                    sample_columns=sample_columns,
                    rls_likely_disabled=True,
                    sample_data=rows,
                )
            if rows:
                return TableResult(
                    name=table,
                    row_count=len(rows),
                    sample_columns=sample_columns,
                    rls_likely_disabled=True,
                    sample_data=rows,
                )
            return TableResult(
                name=table,
                row_count=0,
                error="no rows returned (empty table or access policy)",
            )
        if response.status_code in (401, 403):
            return TableResult(name=table, row_count=None)
        return TableResult(
            name=table,
            row_count=None,
            error=f"HTTP {response.status_code}",
        )
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        logger.debug(
            "Table check failed",
            extra={"event": "table_check_failed", "error_type": type(exc).__name__},
        )
        return TableResult(
            name=table,
            row_count=None,
            error=f"request failed ({type(exc).__name__})",
        )


async def check_tables(
    client: httpx.AsyncClient,
    credential: Credential,
    tables: list[str],
    auth_token: str | None,
) -> list[TableResult]:
    semaphore = asyncio.Semaphore(5)

    async def check_one(table: str) -> TableResult:
        async with semaphore:
            return await check_table_access(client, credential, table, auth_token)

    return await asyncio.gather(*(check_one(table) for table in tables))


async def refresh_auth_token(
    client: httpx.AsyncClient,
    cred: Credential,
    refresh_token: str,
) -> str | None:
    """Exchange a refresh token without logging any reusable token value."""
    try:
        response = await client.post(
            f"{cred.supabase_url}/auth/v1/token?grant_type=refresh_token",
            headers={"apikey": cred.anon_key, "Content-Type": "application/json"},
            json={"refresh_token": refresh_token},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (200, 206):
            token = response.json().get("access_token")
            if isinstance(token, str) and token:
                logger.info("Refreshed auth token successfully")
                return token
        logger.debug("Token refresh failed with HTTP %d", response.status_code)
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        logger.debug(
            "Token refresh error",
            extra={"event": "token_refresh_failed", "error_type": type(exc).__name__},
        )
    return None
