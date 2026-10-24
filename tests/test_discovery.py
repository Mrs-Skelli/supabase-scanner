import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from discovery import (
    DiscoveryProvidersUnavailable,
    DiscoveryTarget,
    _run_outcome,
    _scan_batch,
    discover_targets,
    run_discovery_scan,
)
from scanner import ScanResult, SensitiveKeyExposure


class DiscoveryResilienceTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_or_empty_provider_sets_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            await discover_targets([], 1)
        with self.assertRaisesRegex(ValueError, "unknown discovery source"):
            await discover_targets(["typo"], 1)

    async def test_one_target_exception_does_not_abort_the_batch(self):
        async def fake_scan(url: str) -> ScanResult:
            if "broken" in url:
                raise RuntimeError("raw signed request detail")
            return ScanResult(target_url=url)

        targets = [
            DiscoveryTarget("https://broken.example.test"),
            DiscoveryTarget("https://healthy.example.test"),
        ]
        with (
            patch("discovery.scan", side_effect=fake_scan),
            self.assertLogs("discovery", level="WARNING") as logs,
        ):
            results = await _scan_batch(targets)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].error, "scan failed (RuntimeError)")
        self.assertIsNone(results[1].error)
        self.assertNotIn("raw signed request detail", " ".join(logs.output))

    def test_run_outcome_distinguishes_partial_empty_and_failed_refreshes(self):
        self.assertEqual(
            _run_outcome(
                active_scan=False,
                candidate_count=2,
                provider_status={
                    "shodan": {"status": "error"},
                    "commoncrawl": {"status": "ok"},
                },
            ),
            "partial",
        )
        self.assertEqual(
            _run_outcome(
                active_scan=False,
                candidate_count=0,
                provider_status={"commoncrawl": {"status": "ok"}},
            ),
            "empty",
        )
        self.assertEqual(
            _run_outcome(
                active_scan=False,
                candidate_count=0,
                provider_status={"shodan": {"status": "error"}},
            ),
            "failed",
        )

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

    async def test_wayback_enrichment_is_historical_metadata_not_a_scan(self):
        target = DiscoveryTarget("https://example.test", {"urlscan"})
        historical = {
            target.url: {
                "status": "archived",
                "historical_only": True,
                "capture_timestamp": "20200102030405",
                "confidence": "medium",
                "project_configs": [
                    {
                        "supabase_url": "https://abc.supabase.co",
                        "project_id": "abc",
                        "key_type": "sb_publishable",
                    }
                ],
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            inventory = Path(temp_dir) / "inventory.jsonl"
            status_file = Path(temp_dir) / "discovery-status.json"
            with (
                patch(
                    "discovery.discover_targets",
                    AsyncMock(return_value={target.url: target}),
                ),
                patch(
                    "discovery.wayback_source.enrich_targets",
                    AsyncMock(return_value=historical),
                ),
                patch("discovery._scan_batch", AsyncMock()) as scan_batch,
                patch("discovery.DISCOVERY_STATUS_FILE", status_file),
            ):
                await run_discovery_scan(
                    ["urlscan"],
                    max_per_source=1,
                    batch_size=1,
                    findings_output=Path(temp_dir) / "findings.jsonl",
                    inventory_output=inventory,
                    active_scan=False,
                    wayback_enrich=True,
                )

            record = json.loads(inventory.read_text())
            status = json.loads(status_file.read_text())

        scan_batch.assert_not_awaited()
        self.assertIn("wayback", record["sources"])
        self.assertTrue(record["source_metadata"]["wayback"][0]["historical_only"])
        self.assertEqual(status["providers"]["wayback"]["checked"], 1)
        self.assertEqual(status["scanned"], 0)

    async def test_discovery_only_fails_when_every_provider_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            status_file = Path(temp_dir) / "discovery-status.json"
            with (
                patch(
                    "discovery._discover_shodan",
                    AsyncMock(side_effect=RuntimeError("provider unavailable")),
                ),
                patch("discovery.DISCOVERY_STATUS_FILE", status_file),
            ):
                with self.assertRaises(DiscoveryProvidersUnavailable):
                    await run_discovery_scan(
                        ["shodan"],
                        max_per_source=1,
                        batch_size=1,
                        findings_output=Path(temp_dir) / "findings.jsonl",
                        inventory_output=Path(temp_dir) / "inventory.jsonl",
                        active_scan=False,
                    )

            status = json.loads(status_file.read_text())

        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["candidates"], 0)
        self.assertEqual(status["providers"]["shodan"]["status"], "error")
        self.assertEqual(status["error_type"], "DiscoveryProvidersUnavailable")


if __name__ == "__main__":
    unittest.main()
