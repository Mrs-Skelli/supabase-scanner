import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import shodan

from discovery import ShodanDiscoveryUnavailable, _discover_shodan
from scanner import ScanResult, SensitiveKeyExposure
from shodan_scanner import (
    SHODAN_QUERIES,
    ShodanSourceUnavailable,
    _iter_shodan_targets,
    run_shodan_scan,
    shodan_query_confidence,
)


class FailingShodanAPI:
    def count(self, query: str):
        return {"total": 1}

    def search(self, query: str, page: int):
        raise shodan.APIError("synthetic signed request detail")


class OneResultShodanAPI:
    def count(self, query: str):
        return {"total": 1}

    def search(self, query: str, page: int):
        return {
            "matches": [
                {
                    "ip_str": "203.0.113.10",
                    "port": 443,
                    "hostnames": ["example.test"],
                }
            ]
        }


class ShodanFailureTests(unittest.TestCase):
    def test_queries_include_documented_modern_client_signals(self):
        combined = " ".join(SHODAN_QUERIES)

        self.assertIn("sb_publishable_", combined)
        self.assertIn("NEXT_PUBLIC_SUPABASE_URL", combined)
        self.assertIn("/storage/v1/object/public/", combined)
        self.assertIn("/auth/v1/.well-known/jwks.json", combined)
        self.assertIn("/realtime/v1/websocket", combined)

        self.assertEqual(shodan_query_confidence(SHODAN_QUERIES[0]), "high")
        self.assertEqual(
            shodan_query_confidence('ssl.cert.subject.cn:"*.supabase.co"'),
            "low",
        )

    def test_first_page_error_is_raised_to_the_provider_boundary(self):
        with self.assertRaises(shodan.APIError):
            list(_iter_shodan_targets(FailingShodanAPI(), "query", 10))


class ShodanDiscoveryFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_failed_queries_surface_safe_source_failure(self):
        with (
            patch("discovery._shodan_client", return_value=FailingShodanAPI()),
            patch("discovery.SHODAN_QUERIES", ["one", "two"]),
            self.assertLogs("discovery", level="WARNING") as logs,
        ):
            with self.assertRaises(ShodanDiscoveryUnavailable):
                await _discover_shodan(10)

        output = " ".join(logs.output)
        self.assertIn("APIError", output)
        self.assertNotIn("synthetic signed request detail", output)

    async def test_standalone_scan_fails_when_all_first_pages_fail(self):
        with (
            patch("shodan_scanner._shodan_client", return_value=FailingShodanAPI()),
            self.assertLogs("shodan_scanner", level="WARNING") as logs,
        ):
            with self.assertRaises(ShodanSourceUnavailable):
                await run_shodan_scan(query="custom-query", max_results=1)

        output = " ".join(logs.output)
        self.assertIn("APIError", output)
        self.assertNotIn("synthetic signed request detail", output)

    async def test_sensitive_key_only_result_is_saved(self):
        raw_secret = "sb_secret_" + "s" * 32
        result = ScanResult(
            target_url="https://example.test",
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
            output = Path(temp_dir) / "findings.jsonl"
            with (
                patch(
                    "shodan_scanner._shodan_client", return_value=OneResultShodanAPI()
                ),
                patch("shodan_scanner._scan_batch", return_value=[result]),
            ):
                await run_shodan_scan(
                    query="custom-query",
                    max_results=1,
                    batch_size=1,
                    output_path=output,
                )

            record = json.loads(output.read_text())

        self.assertEqual(record["finding_count"], 1)
        self.assertEqual(record["sensitive_key_exposure_count"], 1)
        self.assertEqual(record["vulnerable_tables"], [])
        self.assertNotIn(raw_secret, json.dumps(record))


if __name__ == "__main__":
    unittest.main()
