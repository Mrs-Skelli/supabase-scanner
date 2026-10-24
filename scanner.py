"""Supabase scan orchestration.

Passive fingerprint extraction and active API probing live in separate modules;
this module is the only layer that connects a fetched site to network probes.
"""

import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from fingerprints import (
    coalesce_sensitive_key_exposures,
    extract_inline_scripts,
    extract_js_urls,
    extract_table_names,
    find_client_config,
    source_label,
)
from scan_models import Credential, ScanResult, SensitiveKeyExposure, TableResult
from ssrf_guard import MAX_REDIRECTS, validate_url
from supabase_probe import (
    HEADERS,
    REQUEST_TIMEOUT,
    build_headers,
    check_table_access,
    check_tables,
    discover_table_names,
    parse_content_range,
    refresh_auth_token,
)

logger = logging.getLogger(__name__)

MAX_JS_SIZE = 5 * 1024 * 1024
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class _TextSource:
    content: str
    label: str


# Compatibility exports for the original single-module API and existing tests.
_build_headers = build_headers
_check_table_rls = check_table_access
_coalesce_sensitive_key_exposures = coalesce_sensitive_key_exposures
_extract_js_urls = extract_js_urls
_extract_table_names_from_js = extract_table_names
_parse_content_range = parse_content_range
_source_label = source_label


def _find_client_config(
    text: str,
    source: str,
) -> tuple[list[Credential], list[SensitiveKeyExposure]]:
    """Extract client config using this module's fail-closed URL validator."""
    return find_client_config(text, source, validate_url)


def _find_credentials(text: str, source: str) -> list[Credential]:
    """Compatibility helper returning only usable public client config."""
    credentials, _ = _find_client_config(text, source)
    return credentials


async def _fetch(client: httpx.AsyncClient, url: str) -> str | None:
    """Fetch one bounded public resource with every redirect revalidated."""
    if validate_url(url):
        logger.warning("SSRF blocked request", extra={"event": "ssrf_blocked"})
        return None

    current_url = url
    try:
        for _ in range(MAX_REDIRECTS):
            response = await client.get(
                current_url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
            )
            if response.status_code in _REDIRECT_STATUSES:
                location = response.headers.get("location")
                if not location:
                    return None
                current_url = urljoin(current_url, location)
                if validate_url(current_url):
                    logger.warning(
                        "SSRF blocked redirect",
                        extra={"event": "ssrf_redirect_blocked"},
                    )
                    return None
                continue
            if response.status_code not in (200, 206):
                return None
            if len(response.content) > MAX_JS_SIZE:
                return None
            return response.text
    except httpx.HTTPError as exc:
        logger.debug(
            "Fetch failed",
            extra={"event": "fetch_failed", "error_type": type(exc).__name__},
        )
        return None

    logger.debug("Too many redirects", extra={"event": "redirect_limit"})
    return None


async def _collect_text_sources(
    client: httpx.AsyncClient,
    target_url: str,
    html: str,
) -> tuple[list[_TextSource], int]:
    """Collect inline, linked, and page text without introducing active probes."""
    js_urls = extract_js_urls(html, target_url)
    fetched = await asyncio.gather(*(_fetch(client, url) for url in js_urls))
    sources = [_TextSource(script, "inline") for script in extract_inline_scripts(html)]
    sources.extend(
        _TextSource(content, source_label(url))
        for url, content in zip(js_urls, fetched, strict=True)
        if content
    )
    sources.append(_TextSource(html, f"{source_label(target_url)} [html]"))
    return sources, len(js_urls)


def _analyze_text_sources(
    sources: list[_TextSource],
) -> tuple[list[Credential], list[SensitiveKeyExposure], set[str]]:
    credentials: list[Credential] = []
    exposures: list[SensitiveKeyExposure] = []
    table_names: set[str] = set()
    seen_credentials: set[tuple[str, str]] = set()

    for source in sources:
        detected_credentials, detected_exposures = _find_client_config(
            source.content, source.label
        )
        for credential in detected_credentials:
            identity = (credential.project_id, credential.anon_key)
            if identity not in seen_credentials:
                seen_credentials.add(identity)
                credentials.append(credential)
        exposures.extend(detected_exposures)
        table_names.update(extract_table_names(source.content))

    return credentials, coalesce_sensitive_key_exposures(exposures), table_names


async def _probe_credentials(
    client: httpx.AsyncClient,
    credentials: list[Credential],
    js_tables: set[str],
    auth_token: str | None,
) -> list[TableResult]:
    table_results: list[TableResult] = []
    seen_projects: set[str] = set()
    for credential in credentials:
        if credential.project_id in seen_projects:
            continue
        seen_projects.add(credential.project_id)

        # Schema discovery remains anonymous; the optional user token is used
        # only for the bounded access comparison.
        tables = await discover_table_names(client, credential, js_tables, None)
        if tables:
            table_results.extend(
                await check_tables(client, credential, tables, auth_token)
            )
    return table_results


async def scan(
    target_url: str,
    auth_token: str | None = None,
    refresh_token: str | None = None,
) -> ScanResult:
    """Fetch one authorized target, fingerprint its client, and check access."""
    if not urlparse(target_url).scheme:
        target_url = f"https://{target_url}"
    result = ScanResult(
        target_url=target_url,
        auth_mode="authenticated" if auth_token else "anon",
    )

    url_error = validate_url(target_url)
    if url_error:
        result.error = f"Blocked: {url_error}"
        return result

    async with httpx.AsyncClient(verify=True) as client:
        html = await _fetch(client, target_url)
        if html is None:
            result.error = "Failed to fetch target URL"
            return result

        sources, result.js_files_scanned = await _collect_text_sources(
            client, target_url, html
        )
        (
            result.credentials,
            result.sensitive_key_exposures,
            js_tables,
        ) = _analyze_text_sources(sources)

        if js_tables:
            logger.info(
                "Extracted table names from JavaScript",
                extra={"event": "js_tables_extracted", "tables": len(js_tables)},
            )
        if not result.credentials:
            return result

        if refresh_token and auth_token:
            fresh_token = await refresh_auth_token(
                client, result.credentials[0], refresh_token
            )
            if fresh_token:
                auth_token = fresh_token
                logger.info("Using refreshed auth token for access checks")

        result.tables_checked = await _probe_credentials(
            client,
            result.credentials,
            js_tables,
            auth_token,
        )
    return result
