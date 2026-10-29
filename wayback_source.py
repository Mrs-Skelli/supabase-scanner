"""Bounded historical Supabase fingerprint enrichment via the Wayback Machine.

This module never requests the live target. It asks the Internet Archive for an
existing capture, inspects a small number of archived assets, and returns only
historical metadata and non-reusable key fingerprints.
"""

import asyncio
import logging
import os
import re
from collections import Counter
from urllib.parse import urlparse

import httpx

from fingerprints import (
    PUBLIC_KEY_RE,
    SECRET_KEY_RE,
    coalesce_sensitive_key_exposures,
    extract_js_urls,
    find_client_config,
    legacy_jwt_role,
    source_label,
)

logger = logging.getLogger(__name__)

WAYBACK_AVAILABILITY_URL = "https://archive.org/wayback/available"
WAYBACK_USER_AGENT = os.getenv(
    "RESEARCH_USER_AGENT", "SupabaseResearchScanner/1.0 (responsible-disclosure)"
)
MAX_ARCHIVE_BODY_BYTES = 5 * 1024 * 1024
MAX_ARCHIVED_ASSETS = 5
MAX_ENRICHMENT_TARGETS = 25
_REPLAY_PATH_RE = re.compile(r"^/web/(?P<timestamp>\d{1,14})(?:[a-z_]+)?/")


class WaybackUnavailable(RuntimeError):
    """Raised when the Internet Archive cannot complete a bounded lookup."""


def _snapshot_replay_url(value: object) -> str | None:
    """Return an archive-only, no-rewrite replay URL."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or parsed.hostname != "web.archive.org":
        return None
    match = _REPLAY_PATH_RE.match(parsed.path)
    if not match:
        return None
    replay_path = _REPLAY_PATH_RE.sub(
        f"/web/{match.group('timestamp')}id_/",
        parsed.path,
        count=1,
    )
    return parsed._replace(
        scheme="https",
        netloc="web.archive.org",
        path=replay_path,
        query="",
        fragment="",
    ).geturl()


async def _get_with_retries(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, str] | None = None,
) -> httpx.Response:
    for attempt in range(3):
        try:
            response = await client.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response
        except httpx.HTTPError:
            if attempt == 2:
                raise WaybackUnavailable("Wayback request unavailable") from None
            await asyncio.sleep(2**attempt)
    raise RuntimeError("unreachable retry state")


async def _available_snapshot(
    client: httpx.AsyncClient,
    url: str,
    timestamp: str | None = None,
) -> dict[str, str] | None:
    params = {"url": url}
    if timestamp:
        params["timestamp"] = timestamp
    response = await _get_with_retries(
        client,
        WAYBACK_AVAILABILITY_URL,
        params=params,
    )
    try:
        payload = response.json()
    except ValueError:
        raise WaybackUnavailable("Wayback returned invalid JSON") from None
    closest = (payload.get("archived_snapshots") or {}).get("closest")
    if not isinstance(closest, dict) or closest.get("available") is not True:
        return None
    replay_url = _snapshot_replay_url(closest.get("url"))
    capture_timestamp = closest.get("timestamp")
    if not replay_url or not isinstance(capture_timestamp, str):
        return None
    return {
        "replay_url": replay_url,
        "capture_url": str(closest.get("url")),
        "timestamp": capture_timestamp,
        "status": str(closest.get("status", "")),
    }


async def _fetch_archived_text(
    client: httpx.AsyncClient,
    replay_url: str,
) -> str | None:
    for attempt in range(3):
        try:
            async with client.stream("GET", replay_url, timeout=30) as response:
                response.raise_for_status()
                if not 200 <= response.status_code < 300:
                    return None
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_ARCHIVE_BODY_BYTES:
                    return None
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > MAX_ARCHIVE_BODY_BYTES:
                        return None
                    body.extend(chunk)
                return bytes(body).decode("utf-8", errors="ignore")
        except ValueError:
            return None
        except httpx.HTTPError:
            if attempt == 2:
                raise WaybackUnavailable("Wayback capture unavailable") from None
            await asyncio.sleep(2**attempt)
    raise RuntimeError("unreachable retry state")


def _key_types(text: str) -> list[str]:
    types: set[str] = set()
    for value in PUBLIC_KEY_RE.findall(text):
        if value.startswith("sb_publishable_"):
            types.add("sb_publishable")
        elif role := legacy_jwt_role(value):
            types.add(f"legacy_{role}")
    if SECRET_KEY_RE.search(text):
        types.add("sb_secret")
    return sorted(types)


def _inspect_archived_text(text: str, source: str) -> dict:
    # Archive payloads are evidence only. The injected validator allows parsing
    # but the returned credentials are never passed to the live probe layer.
    credentials, exposures = find_client_config(text, source, lambda _url: None)
    project_configs = [
        {
            "supabase_url": credential.supabase_url,
            "project_id": credential.project_id,
            "key_type": (
                "sb_publishable"
                if credential.anon_key.startswith("sb_publishable_")
                else "legacy_anon"
            ),
        }
        for credential in credentials
    ]
    return {
        "project_configs": project_configs,
        "key_types": _key_types(text),
        "sensitive_key_exposures": exposures,
    }


async def enrich_target(
    target_url: str,
    *,
    max_assets: int = MAX_ARCHIVED_ASSETS,
) -> dict:
    """Inspect the closest archived page and a bounded set of archived scripts."""
    if max_assets < 0 or max_assets > MAX_ARCHIVED_ASSETS:
        raise ValueError(f"max_assets must be between 0 and {MAX_ARCHIVED_ASSETS}")

    headers = {"User-Agent": WAYBACK_USER_AGENT}
    async with httpx.AsyncClient(headers=headers, follow_redirects=False) as client:
        snapshot = await _available_snapshot(client, target_url)
        if not snapshot:
            return {
                "status": "not_archived",
                "historical_only": True,
                "confidence": "low",
                "assets_checked": 0,
                "project_configs": [],
                "key_types": [],
                "sensitive_key_exposures": [],
            }

        page = await _fetch_archived_text(client, snapshot["replay_url"])
        if page is None:
            raise WaybackUnavailable("Wayback capture unavailable")

        inspected = [
            _inspect_archived_text(page, source_label(target_url)),
        ]
        assets_checked = 0
        for asset_url in extract_js_urls(page, target_url)[:max_assets]:
            await asyncio.sleep(0.25)
            asset_snapshot = await _available_snapshot(
                client,
                asset_url,
                snapshot["timestamp"],
            )
            if not asset_snapshot:
                continue
            archived_asset = await _fetch_archived_text(
                client,
                asset_snapshot["replay_url"],
            )
            if archived_asset is None:
                continue
            assets_checked += 1
            inspected.append(
                _inspect_archived_text(archived_asset, source_label(asset_url))
            )

    projects = {
        (item["supabase_url"], item["project_id"], item["key_type"]): item
        for result in inspected
        for item in result["project_configs"]
    }
    key_types = sorted(
        {key_type for result in inspected for key_type in result["key_types"]}
    )
    exposures = coalesce_sensitive_key_exposures(
        [
            exposure
            for result in inspected
            for exposure in result["sensitive_key_exposures"]
        ]
    )
    exposure_records = [
        {
            "key_type": exposure.key_type,
            "occurrence_count": exposure.occurrence_count,
            "source_file": exposure.source_file,
            "fingerprint": exposure.fingerprint,
        }
        for exposure in exposures
    ]
    signals = Counter()
    if projects:
        signals["archived_client_config"] += len(projects)
    if key_types:
        signals["archived_key_format"] += len(key_types)
    if exposure_records:
        signals["archived_privileged_key"] += sum(
            item["occurrence_count"] for item in exposure_records
        )

    return {
        "status": "archived",
        "historical_only": True,
        "capture_timestamp": snapshot["timestamp"],
        "capture_url": snapshot["capture_url"],
        "confidence": "medium" if projects or exposure_records else "low",
        "assets_checked": assets_checked + 1,
        "signals": dict(signals),
        "project_configs": sorted(
            projects.values(),
            key=lambda item: (
                item["supabase_url"],
                item["project_id"],
                item["key_type"],
            ),
        ),
        "key_types": key_types,
        "sensitive_key_exposures": exposure_records,
    }


async def enrich_targets(
    target_urls: list[str],
    *,
    max_targets: int = MAX_ENRICHMENT_TARGETS,
    max_assets: int = MAX_ARCHIVED_ASSETS,
) -> dict[str, dict]:
    """Enrich a bounded candidate list serially to stay polite to the Archive."""
    if max_targets < 1:
        raise ValueError("max_targets must be at least 1")
    results: dict[str, dict] = {}
    for index, target_url in enumerate(target_urls[:max_targets]):
        if index:
            await asyncio.sleep(0.25)
        try:
            results[target_url] = await enrich_target(
                target_url,
                max_assets=max_assets,
            )
        except Exception as exc:
            error_type = type(exc).__name__
            logger.warning(
                "Wayback enrichment unavailable",
                extra={
                    "event": "wayback_enrichment_failed",
                    "error_type": error_type,
                },
            )
            results[target_url] = {
                "status": "error",
                "historical_only": True,
                "error_type": error_type,
            }
    return results
