"""Concurrent target scanning with per-target failure isolation."""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable

from observability import record_error
from scan_models import ScanResult

ScanCallable = Callable[[str], Awaitable[ScanResult]]


async def scan_urls(
    urls: Iterable[str],
    scan_one: ScanCallable,
    logger: logging.Logger,
) -> list[ScanResult]:
    """Run target scans concurrently without exposing exception values."""

    async def safely_scan(url: str) -> ScanResult:
        try:
            return await scan_one(url)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error_type = type(exc).__name__
            record_error("scanner", error_type, "target_scan_failed")
            logger.warning(
                "Target scan failed",
                extra={
                    "event": "target_scan_failed",
                    "error_type": error_type,
                },
            )
            return ScanResult(
                target_url=url,
                error=f"scan failed ({error_type})",
            )

    return await asyncio.gather(*(safely_scan(url) for url in urls))
