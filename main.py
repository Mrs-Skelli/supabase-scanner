"""
FastAPI backend for the Supabase RLS Scanner web interface.
Mounted under /supabase via Apache reverse proxy.
"""

import asyncio
import base64
import binascii
import copy
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from finding_store import load_latest_findings, matches_query, summarize_finding
from masking import EvidenceConfig, credential_preview, prepare_sample_data
from observability import (
    bind_operation,
    bind_request,
    configure_logging,
    increment_counter,
    new_id,
    normalize_request_id,
    read_status_file,
    record_error,
    reset_operation,
    reset_request,
    runtime_snapshot,
)
from scan_models import ScanResult
from scanner import scan

limiter = Limiter(key_func=get_remote_address)
BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = Path(os.getenv("RESULTS_DIR", BASE_DIR / "results"))
DISCOVERY_STATUS_FILE = RESULTS_DIR / "diagnostics" / "discovery-status.json"
LOG_FILE = configure_logging("api", BASE_DIR)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "API service starting",
        extra={"event": "service_start", "log_file_enabled": LOG_FILE is not None},
    )
    yield
    logger.info("API service stopping", extra={"event": "service_stop"})


app = FastAPI(
    title="Supabase RLS Scanner",
    description="Security research tool for reviewing Supabase access evidence",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.middleware("http")
async def request_observability(request: Request, call_next):
    request_id = normalize_request_id(request.headers.get("x-request-id"))
    token = bind_request(request_id)
    started = time.perf_counter()
    increment_counter("http_requests_total")
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    except Exception as exc:
        record_error("api", type(exc).__name__, "unhandled_request")
        logger.exception(
            "Unhandled request error",
            extra={
                "event": "unhandled_request",
                "method": request.method,
                "path": request.url.path,
                "error_type": type(exc).__name__,
            },
        )
        raise
    finally:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        if status_code >= 500:
            increment_counter("http_5xx_total")
        elif status_code >= 400:
            increment_counter("http_4xx_total")
        logger.debug(
            "Request completed",
            extra={
                "event": "request_completed",
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": duration_ms,
            },
        )
        reset_request(token)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


def _clean_token(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().replace("\n", "").replace("\r", "")
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()
    return cleaned or None


def _decode_auth_blob(value: str) -> tuple[str | None, str | None]:
    """Decode a Supabase auth-cookie blob without retaining cross-request state."""
    has_cookie_prefix = value.startswith("base64-")
    encoded = value.removeprefix("base64-")
    if not has_cookie_prefix and (encoded.startswith("eyJ") or len(encoded) <= 200):
        return value, None
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return value, None
    if not isinstance(decoded, dict):
        return value, None
    return _clean_token(decoded.get("access_token")), _clean_token(
        decoded.get("refresh_token")
    )


class ScanRequest(BaseModel):
    auth_token: str | None = None
    refresh_token: str | None = None
    raw_evidence: bool = False
    url: str

    @model_validator(mode="after")
    def normalize_auth(self) -> "ScanRequest":
        token = _clean_token(self.auth_token)
        refresh = _clean_token(self.refresh_token)
        if token:
            token, embedded_refresh = _decode_auth_blob(token)
            refresh = refresh or embedded_refresh
        self.auth_token = token
        self.refresh_token = refresh
        return self

    @field_validator("url")
    @classmethod
    def normalize_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v


class CredentialResponse(BaseModel):
    supabase_url: str
    project_id: str
    anon_key_preview: str
    source_file: str


class SensitiveKeyExposureResponse(BaseModel):
    key_type: str
    occurrence_count: int
    source_file: str
    fingerprint: str


class TableResponse(BaseModel):
    name: str
    row_count: int | None
    sample_columns: list[str]
    rls_likely_disabled: bool
    error: str | None
    sample_data: list[dict[str, Any]] = Field(default_factory=list)


class ScanResponse(BaseModel):
    target_url: str
    found_credentials: bool
    js_files_scanned: int
    credentials: list[CredentialResponse]
    sensitive_key_exposures: list[SensitiveKeyExposureResponse]
    tables_checked: list[TableResponse]
    vulnerable_table_count: int
    auth_mode: str
    evidence_mode: str
    error: str | None


def _serialize_result(result: ScanResult, raw_requested: bool = False) -> ScanResponse:
    evidence = EvidenceConfig.from_environment()
    show_raw = raw_requested and evidence.raw_values
    creds = []
    for c in result.credentials:
        creds.append(
            CredentialResponse(
                supabase_url=c.supabase_url,
                project_id=c.project_id,
                anon_key_preview=credential_preview(c.anon_key),
                source_file=c.source_file,
            )
        )

    tables = [
        TableResponse(
            name=t.name,
            row_count=t.row_count,
            sample_columns=t.sample_columns,
            rls_likely_disabled=t.rls_likely_disabled,
            error=t.error,
            sample_data=prepare_sample_data(
                t.sample_data,
                raw_values=show_raw,
                limit=evidence.sample_limit,
            ),
        )
        for t in result.tables_checked
    ]

    return ScanResponse(
        target_url=result.target_url,
        found_credentials=result.found_credentials,
        js_files_scanned=result.js_files_scanned,
        credentials=creds,
        sensitive_key_exposures=[
            SensitiveKeyExposureResponse(
                key_type=exposure.key_type,
                occurrence_count=exposure.occurrence_count,
                source_file=exposure.source_file,
                fingerprint=exposure.fingerprint,
            )
            for exposure in result.sensitive_key_exposures
        ],
        tables_checked=tables,
        vulnerable_table_count=len(result.vulnerable_tables),
        auth_mode=result.auth_mode,
        evidence_mode="raw" if show_raw else "masked",
        error=result.error,
    )


@app.get("/", response_class=HTMLResponse)
async def index():
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/browse", response_class=HTMLResponse)
async def browse():
    return (BASE_DIR / "static" / "browse.html").read_text(encoding="utf-8")


@app.get("/diagnostics", response_class=HTMLResponse)
async def diagnostics_page():
    return (BASE_DIR / "static" / "diagnostics.html").read_text(encoding="utf-8")


@app.post("/api/scan", response_model=ScanResponse)
@limiter.limit("10/minute")
async def api_scan(request: Request, body: ScanRequest):
    """
    Scan a URL for public Supabase client config and bounded access evidence.
    Rate limited to 10 scans/minute per IP.
    """
    operation_id = new_id("scan")
    operation_token = bind_operation(operation_id)
    started = time.perf_counter()
    increment_counter("scans_started_total")
    logger.info(
        "Scan started",
        extra={
            "event": "scan_started",
            "auth_mode": "authenticated" if body.auth_token else "anon",
            "raw_evidence_requested": body.raw_evidence,
        },
    )
    try:
        result = await asyncio.wait_for(
            scan(
                body.url,
                auth_token=body.auth_token,
                refresh_token=body.refresh_token,
            ),
            timeout=60,
        )
    except TimeoutError:
        increment_counter("scans_timed_out_total")
        record_error("scanner", "TimeoutError", "scan_timeout")
        logger.warning(
            "Scan timed out",
            extra={"event": "scan_timeout"},
        )
        raise HTTPException(
            status_code=504, detail="Scan timed out after 60 seconds"
        ) from None
    except Exception as exc:
        increment_counter("scans_failed_total")
        record_error("scanner", type(exc).__name__, "scan_failed")
        logger.exception(
            "Scan failed",
            extra={
                "event": "scan_failed",
                "error_type": type(exc).__name__,
            },
        )
        raise HTTPException(status_code=500, detail="Internal scan error") from exc
    else:
        increment_counter("scans_completed_total")
        if result.error:
            increment_counter("scans_completed_with_error_total")
        logger.info(
            "Scan completed",
            extra={
                "event": "scan_completed",
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "js_files_scanned": result.js_files_scanned,
                "public_configs": len(result.credentials),
                "tables_checked": len(result.tables_checked),
                "readable_tables": len(result.vulnerable_tables),
                "sensitive_key_exposures": sum(
                    item.occurrence_count for item in result.sensitive_key_exposures
                ),
                "result_error": bool(result.error),
            },
        )
        return _serialize_result(result, raw_requested=body.raw_evidence)
    finally:
        reset_operation(operation_token)


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/diagnostics")
async def diagnostics():
    """Derived operational state only; the reverse proxy protects this route."""
    evidence = EvidenceConfig.from_environment()
    payload = runtime_snapshot()
    payload.update(
        {
            "service": "supabase-scanner",
            "evidence": {
                "raw_enabled": evidence.raw_values,
                "sample_limit": evidence.sample_limit,
            },
            "storage": {
                "unique_findings": len(_load_findings()),
                "log_file_enabled": LOG_FILE is not None,
            },
            "latest_discovery": read_status_file(DISCOVERY_STATUS_FILE),
        }
    )
    return JSONResponse(
        payload,
        headers={
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
        },
    )


# ── Findings browser ────────────────────────────────────────────────────────
# Read-only views over the cron-discovered findings. Masked evidence is always
# the default. Bounded raw values are available only when explicitly enabled in
# the deployment and explicitly requested by the analyst UI.


def _has_samples(rec: dict) -> bool:
    return any(
        bool(table.get("sample_data"))
        for table in rec.get("vulnerable_tables", []) or []
    )


def _record_for_view(rec: dict, raw_requested: bool) -> tuple[dict, str, bool]:
    """Return an isolated, bounded record for masked or analyst display."""
    evidence = EvidenceConfig.from_environment()
    rendered = copy.deepcopy(rec)
    stored_raw = (
        rec.get("sample_mode") == "raw_secrets_redacted" or rec.get("masked") is False
    )
    raw_available = evidence.raw_values and stored_raw and _has_samples(rec)
    show_raw = raw_requested and raw_available
    for bucket in ("vulnerable_tables", "tables_checked"):
        for table in rendered.get(bucket, []) or []:
            table["sample_data"] = prepare_sample_data(
                table.get("sample_data") or [],
                raw_values=show_raw,
                limit=evidence.sample_limit,
            )
    rendered["masked"] = not show_raw
    rendered["sample_mode"] = "raw_secrets_redacted" if show_raw else "masked"
    return rendered, ("raw" if show_raw else "masked"), raw_available


def _load_findings() -> list[dict]:
    """All reportable findings, de-duplicated by target."""
    return load_latest_findings(RESULTS_DIR)


@app.get("/api/findings")
async def list_findings(q: str | None = None, limit: int = 50, offset: int = 0):
    """Paginated reportable findings with an optional substring filter."""
    findings = _load_findings()
    if q:
        findings = [record for record in findings if matches_query(record, q)]
    total = len(findings)
    page = findings[offset : offset + max(1, min(limit, 200))]
    payload = {
        "total": total,
        "offset": offset,
        "limit": limit,
        "results": [summarize_finding(record) for record in page],
    }
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


@app.get("/api/findings/detail")
async def finding_detail(target: str, raw: bool = False):
    """Bounded detail for one target; raw application values require opt-in."""
    for rec in _load_findings():
        if rec.get("target") == target:
            rendered, evidence_mode, raw_available = _record_for_view(rec, raw)
            creds = []
            for c in rendered.get("credentials", []) or []:
                c = dict(c)
                if "anon_key" in c:
                    c["anon_key_preview"] = credential_preview(c.pop("anon_key") or "")
                creds.append(c)
            payload = {
                "target": rendered.get("target"),
                "timestamp": rendered.get("timestamp"),
                "sources": rendered.get("sources", []),
                "discovery_confidence": rendered.get("discovery_confidence", "unknown"),
                "credentials": creds,
                "sensitive_key_exposures": rendered.get("sensitive_key_exposures", []),
                "vulnerable_tables": rendered.get("vulnerable_tables", []),
                "evidence_mode": evidence_mode,
                "raw_available": raw_available,
            }
            return JSONResponse(
                payload,
                headers={
                    "Cache-Control": "no-store, private",
                    "Pragma": "no-cache",
                    "Referrer-Policy": "no-referrer",
                },
            )
    raise HTTPException(status_code=404, detail="target not found")
