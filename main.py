"""
FastAPI backend for the Supabase RLS Scanner web interface.
Mounted under /supabase via Apache reverse proxy.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from scanner import ScanResult, scan

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Supabase RLS Scanner starting up")
    yield
    logger.info("Supabase RLS Scanner shutting down")


app = FastAPI(
    title="Supabase RLS Scanner",
    description="Security research tool for identifying exposed Supabase data",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


class ScanRequest(BaseModel):
    auth_token: str | None = None  # Optional JWT for authenticated RLS testing
    url: str

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


class TableResponse(BaseModel):
    name: str
    row_count: int | None
    sample_columns: list[str]
    rls_likely_disabled: bool
    error: str | None


class ScanResponse(BaseModel):
    target_url: str
    found_credentials: bool
    js_files_scanned: int
    credentials: list[CredentialResponse]
    tables_checked: list[TableResponse]
    vulnerable_table_count: int
    auth_mode: str
    error: str | None


def _serialize_result(result: ScanResult) -> ScanResponse:
    creds = []
    for c in result.credentials:
        key = c.anon_key
        preview = key[:20] + "..." + key[-10:] if len(key) > 32 else key
        creds.append(CredentialResponse(
            supabase_url=c.supabase_url,
            project_id=c.project_id,
            anon_key_preview=preview,
            source_file=c.source_file,
        ))

    tables = [
        TableResponse(
            name=t.name,
            row_count=t.row_count,
            sample_columns=t.sample_columns,
            rls_likely_disabled=t.rls_likely_disabled,
            error=t.error,
        )
        for t in result.tables_checked
    ]

    return ScanResponse(
        target_url=result.target_url,
        found_credentials=result.found_credentials,
        js_files_scanned=result.js_files_scanned,
        credentials=creds,
        tables_checked=tables,
        vulnerable_table_count=len(result.vulnerable_tables),
        auth_mode=result.auth_mode,
        error=result.error,
    )


@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html") as f:
        return f.read()


@app.post("/api/scan", response_model=ScanResponse)
@limiter.limit("10/minute")
async def api_scan(request: Request, body: ScanRequest):
    """
    Scan a URL for exposed Supabase credentials and disabled RLS.
    Rate limited to 10 scans/minute per IP.
    """
    logger.info("Scan requested for: %s (from %s)", body.url, get_remote_address(request))
    try:
        result = await asyncio.wait_for(scan(body.url, auth_token=body.auth_token), timeout=60)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Scan timed out after 60 seconds")
    except Exception as exc:
        logger.exception("Scan error for %s", body.url)
        raise HTTPException(status_code=500, detail=str(exc))

    return _serialize_result(result)


@app.get("/api/health")
async def health():
    return {"status": "ok"}
