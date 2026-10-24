import json
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

        with (
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
            targets = await discover_targets(["shodan", "commoncrawl", "builtwith"], 10)

        self.assertEqual(list(targets), ["https://example.test"])
        self.assertEqual(targets["https://example.test"].sources, {"shodan"})

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
            with (
                patch(
                    "discovery.discover_targets",
                    AsyncMock(return_value={target.url: target}),
                ),
                patch("discovery._scan_batch", AsyncMock(return_value=[result])),
            ):
                await run_discovery_scan(
                    ["shodan"],
                    max_per_source=1,
                    batch_size=1,
                    findings_output=findings,
                    inventory_output=inventory,
                )

            record = json.loads(findings.read_text())

        self.assertEqual(record["status"], "finding")
        self.assertEqual(record["finding_count"], 1)
        self.assertEqual(record["sensitive_key_exposure_count"], 1)
        self.assertEqual(record["vulnerable_tables"], [])
        self.assertNotIn(raw_secret, json.dumps(record))


if __name__ == "__main__":
    unittest.main()
