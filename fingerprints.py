"""Passive Supabase client fingerprint extraction.

This module only parses supplied text. URL validation is injected by the caller
before a detected endpoint can become an active scan credential.
"""

import base64
import binascii
import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from scan_models import Credential, SensitiveKeyExposure

UrlValidator = Callable[[str], str | None]

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
TABLE_FROM_RE = re.compile(r'\.from\(\s*["\x27]([a-zA-Z_][a-zA-Z0-9_]*)["\x27]\s*\)')

MAX_CONFIG_PAIR_DISTANCE = 500
MAX_SERVICE_PAIR_DISTANCE = 1500
MAX_JS_FILES = 40

_NON_TABLE_IDENTIFIERS = frozenset(
    {
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
)


def source_label(url: str) -> str:
    """Return a URL label without query parameters, fragments, or userinfo."""
    try:
        parsed = urlparse(url)
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return "[invalid-url]"
    if not parsed.hostname:
        return "[invalid-url]"
    return f"{parsed.scheme}://{parsed.hostname}{port}{parsed.path}"


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """Extract bounded JavaScript URLs from script and preload tags."""
    soup = BeautifulSoup(html, "html.parser")
    urls: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"].strip()
        if not src.startswith("data:"):
            urls.append(urljoin(base_url, src))
    for tag in soup.find_all("link", rel=True):
        rels = tag.get("rel", [])
        is_script_preload = "modulepreload" in rels or (
            "preload" in rels and tag.get("as") == "script"
        )
        if not is_script_preload:
            continue
        href = tag.get("href", "").strip()
        if href and not href.startswith("data:"):
            urls.append(urljoin(base_url, href))
    return list(dict.fromkeys(urls))[:MAX_JS_FILES]


def extract_inline_scripts(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    return [tag.string for tag in soup.find_all("script", src=False) if tag.string]


def extract_table_names(text: str) -> set[str]:
    """Extract plausible table names from Supabase `.from()` calls."""
    return {
        table
        for table in TABLE_FROM_RE.findall(text)
        if table not in _NON_TABLE_IDENTIFIERS and len(table) > 1
    }


def legacy_jwt_role(key: str) -> str | None:
    """Read a legacy JWT role without verifying or using the token."""
    try:
        payload = key.split(".", maxsplit=2)[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (binascii.Error, IndexError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(claims, dict):
        return None
    role = claims.get("role")
    return role if isinstance(role, str) else None


def is_public_client_key(key: str) -> bool:
    if SECRET_KEY_RE.fullmatch(key):
        return False
    if key.startswith("sb_publishable_"):
        return bool(PUBLIC_KEY_RE.fullmatch(key))
    return bool(PUBLIC_KEY_RE.fullmatch(key)) and legacy_jwt_role(key) == "anon"


def key_fingerprint(value: str) -> str:
    """Return a short one-way correlation fingerprint."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def sensitive_key_exposures(text: str, source: str) -> list[SensitiveKeyExposure]:
    detected: Counter[tuple[str, str]] = Counter()
    for value in SECRET_KEY_RE.findall(text):
        detected[("sb_secret", key_fingerprint(value))] += 1
    for value in PUBLIC_KEY_RE.findall(text):
        role = legacy_jwt_role(value)
        if role in {"service_role", "supabase_admin"}:
            detected[(f"legacy_{role}", key_fingerprint(value))] += 1
    return [
        SensitiveKeyExposure(
            key_type=key_type,
            occurrence_count=count,
            source_file=source,
            fingerprint=fingerprint,
        )
        for (key_type, fingerprint), count in sorted(detected.items())
    ]


def coalesce_sensitive_key_exposures(
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


def _normalize_supabase_url(value: str, validate_url: UrlValidator) -> str | None:
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    normalized = parsed._replace(query="", fragment="").geturl().rstrip("/")
    return None if validate_url(normalized) else normalized


def _origin_from_service_url(value: str) -> str | None:
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
        return None
    scheme = {"ws": "http", "wss": "https"}.get(parsed.scheme, parsed.scheme)
    return f"{scheme}://{parsed.netloc}"


def _project_id_for_url(supabase_url: str) -> str:
    hostname = urlparse(supabase_url).hostname or "unknown"
    for hosted_suffix in (".supabase.co", ".supabase.in"):
        if hostname.lower().endswith(hosted_suffix):
            return hostname[: -len(hosted_suffix)]
    return hostname


def _credential_from_pair(
    url: str,
    key: str,
    source: str,
    validate_url: UrlValidator,
) -> Credential | None:
    if not is_public_client_key(key):
        return None
    supabase_url = _normalize_supabase_url(url, validate_url)
    if not supabase_url:
        return None
    return Credential(
        supabase_url=supabase_url,
        project_id=_project_id_for_url(supabase_url),
        anon_key=key,
        source_file=source,
    )


def find_client_config(
    text: str,
    source: str,
    validate_url: UrlValidator,
) -> tuple[list[Credential], list[SensitiveKeyExposure]]:
    """Return safe public client configs plus non-reusable secret metadata."""
    pairs: set[tuple[str, str]] = {
        (match.group("url"), match.group("key"))
        for match in CREATE_CLIENT_RE.finditer(text)
    }

    url_configs = list(SUPABASE_URL_CONFIG_RE.finditer(text))
    key_configs = list(SUPABASE_KEY_CONFIG_RE.finditer(text))
    for url_match in url_configs:
        for key_match in key_configs:
            if abs(url_match.start() - key_match.start()) <= MAX_CONFIG_PAIR_DISTANCE:
                pairs.add((url_match.group("url"), key_match.group("key")))

    key_matches = [
        *PUBLIC_KEY_RE.finditer(text),
        *SECRET_KEY_RE.finditer(text),
    ]
    for service_match in SUPABASE_SERVICE_URL_RE.finditer(text):
        origin = _origin_from_service_url(service_match.group("url"))
        if not origin:
            continue
        for key_match in key_matches:
            if (
                abs(service_match.start() - key_match.start())
                <= MAX_SERVICE_PAIR_DISTANCE
            ):
                pairs.add((origin, key_match.group(0)))

    hosted_urls = set(SUPABASE_URL_RE.findall(text))
    public_keys = set(PUBLIC_KEY_RE.findall(text))
    pairs.update((url, key) for url in hosted_urls for key in public_keys)

    credentials = [
        credential
        for url, key in sorted(pairs)
        if (credential := _credential_from_pair(url, key, source, validate_url))
    ]
    return credentials, sensitive_key_exposures(text, source)
