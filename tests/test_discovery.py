import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from discovery import DiscoveryTarget, discover_targets, run_discovery_scan
from scanner import ScanResult, SensitiveKeyExposure


class DiscoveryResilienceTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_provider_does_not_discard_other_results(self):
        shodan_result = [
            {
                "url": "https://example.test/path",
                "source": "shodan",
                "metadata": {"query": "supabase"},
            }
        ]

        provider_status = {}
        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "discovery._discover_shodan",
                AsyncMock(return_value=shodan_result),
            ),
            patch(
                "discovery.commoncrawl_source.discover_targets",
                AsyncMock(side_effect=RuntimeError("temporary disconnect")),
            ),
            patch(
                "discovery.builtwith_source.discover_targets",
                AsyncMock(return_value=[]),
            ),
        ):
            targets = await discover_targets(
                ["shodan", "commoncrawl", "builtwith"], 10, provider_status
            )

        self.assertEqual(list(targets), ["https://example.test"])
        self.assertEqual(targets["https://example.test"].sources, {"shodan"})
        self.assertEqual(provider_status["shodan"]["status"], "ok")
        self.assertEqual(provider_status["common_crawl"]["status"], "error")
        self.assertEqual(provider_status["builtwith"]["status"], "disabled")

    async def test_sensitive_key_only_result_is_written_as_a_finding(self):
        raw_secret = "sb_secret_" + "s" * 32
        target = DiscoveryTarget("https://example.test", {"shodan"})
        result = ScanResult(
            target_url=target.url,
            sensitive_key_exposures=[
                SensitiveKeyExposure(
                    key_type="sb_secret",
                    occurrence_count=1,
                    source_file="fixture.js",
                    fingerprint="0123456789abcdef",
                )
            ],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            findings = Path(temp_dir) / "findings.jsonl"
            inventory = Path(temp_dir) / "inventory.jsonl"
            status_file = Path(temp_dir) / "discovery-status.json"
            with (
                patch(
                    "discovery.discover_targets",
                    AsyncMock(return_value={target.url: target}),
                ),
                patch("discovery._scan_batch", AsyncMock(return_value=[result])),
                patch("discovery.DISCOVERY_STATUS_FILE", status_file),
            ):
                await run_discovery_scan(
                    ["shodan"],
                    max_per_source=1,
                    batch_size=1,
                    findings_output=findings,
                    inventory_output=inventory,
                )

            record = json.loads(findings.read_text())
            status = json.loads(status_file.read_text())

        self.assertEqual(record["status"], "finding")
        self.assertEqual(record["finding_count"], 1)
        self.assertEqual(record["sensitive_key_exposure_count"], 1)
        self.assertEqual(record["vulnerable_tables"], [])
        self.assertNotIn(raw_secret, json.dumps(record))
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["candidates"], 1)
        self.assertEqual(status["scanned"], 1)
        self.assertEqual(status["findings"], 1)

    async def test_discovery_only_writes_candidates_without_scanning(self):
        target = DiscoveryTarget("https://example.test", {"commoncrawl"})
        target.metadata["commoncrawl"].append(
            {"marker": "sb_publishable", "confidence": "high"}
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            findings = Path(temp_dir) / "findings.jsonl"
            inventory = Path(temp_dir) / "inventory.jsonl"
            status_file = Path(temp_dir) / "discovery-status.json"
            with (
                patch(
                    "discovery.discover_targets",
                    AsyncMock(return_value={target.url: target}),
                ),
                patch("discovery._scan_batch", AsyncMock()) as scan_batch,
                patch("discovery.DISCOVERY_STATUS_FILE", status_file),
            ):
                await run_discovery_scan(
                    ["commoncrawl"],
                    max_per_source=1,
                    batch_size=1,
                    findings_output=findings,
                    inventory_output=inventory,
                    active_scan=False,
                )

            record = json.loads(inventory.read_text())
            status = json.loads(status_file.read_text())

        scan_batch.assert_not_awaited()
        self.assertFalse(findings.exists())
        self.assertEqual(record["status"], "candidate")
        self.assertEqual(record["discovery_confidence"], "high")
        self.assertEqual(record["sources"], ["commoncrawl"])
        self.assertEqual(status["status"], "discovered")
        self.assertEqual(status["candidates"], 1)
        self.assertEqual(status["scanned"], 0)


if __name__ == "__main__":
    unittest.main()
