import asyncio
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from discovery import DiscoveryTarget, _serialize_result, discover_targets
from main import _record_for_view
from masking import SECRET_REDACTION, prepare_sample_data


class EvidenceMaskingTests(unittest.TestCase):
    def test_raw_evidence_preserves_application_values_and_redacts_secrets(self):
        rows = [{
            "id": 42,
            "email": "analyst@example.test",
            "display_name": "Example Person",
            "access_token": "not-safe-to-display",
            "metadata": {
                "city": "Amsterdam",
                "password_hash": "also-not-safe",
            },
            "innocent_field": "eyJabcdefghijk.abcdefghijk.abcdefghijk",
        }]

        evidence = prepare_sample_data(rows, raw_values=True, limit=1)[0]

        self.assertEqual(evidence["id"], 42)
        self.assertEqual(evidence["email"], "analyst@example.test")
        self.assertEqual(evidence["display_name"], "Example Person")
        self.assertEqual(evidence["metadata"]["city"], "Amsterdam")
        self.assertEqual(evidence["access_token"], SECRET_REDACTION)
        self.assertEqual(evidence["metadata"]["password_hash"], SECRET_REDACTION)
        self.assertEqual(evidence["innocent_field"], SECRET_REDACTION)

    def test_sample_limit_is_bounded(self):
        rows = [{"id": value} for value in range(10)]
        self.assertEqual(len(prepare_sample_data(rows, raw_values=True, limit=99)), 3)

    def test_discovery_defaults_to_masked_storage(self):
        table = SimpleNamespace(
            name="profiles",
            row_count=1,
            sample_columns=["email"],
            rls_likely_disabled=True,
            error=None,
            sample_data=[{"email": "analyst@example.test"}],
        )
        result = SimpleNamespace(
            target_url="https://example.test",
            vulnerable_tables=[table],
            tables_checked=[table],
            error=None,
            auth_mode="anon",
            js_files_scanned=1,
            credentials=[],
        )

        with patch.dict(os.environ, {}, clear=True):
            record = _serialize_result(result, DiscoveryTarget("https://example.test"))

        self.assertTrue(record["masked"])
        self.assertEqual(record["sample_mode"], "masked")
        self.assertNotEqual(
            record["vulnerable_tables"][0]["sample_data"][0]["email"],
            "analyst@example.test",
        )

    def test_discovery_raw_mode_is_explicit_and_still_redacts_tokens(self):
        table = SimpleNamespace(
            name="profiles",
            row_count=1,
            sample_columns=["email", "api_key"],
            rls_likely_disabled=True,
            error=None,
            sample_data=[{
                "email": "analyst@example.test",
                "api_key": "not-safe-to-display",
            }],
        )
        result = SimpleNamespace(
            target_url="https://example.test",
            vulnerable_tables=[table],
            tables_checked=[table],
            error=None,
            auth_mode="anon",
            js_files_scanned=1,
            credentials=[],
        )

        with patch.dict(os.environ, {"RAW_EVIDENCE_ENABLED": "true"}, clear=True):
            record = _serialize_result(result, DiscoveryTarget("https://example.test"))

        sample = record["vulnerable_tables"][0]["sample_data"][0]
        self.assertFalse(record["masked"])
        self.assertEqual(record["sample_mode"], "raw_secrets_redacted")
        self.assertEqual(sample["email"], "analyst@example.test")
        self.assertEqual(sample["api_key"], SECRET_REDACTION)

    def test_browser_defaults_to_masked_and_requires_explicit_raw_request(self):
        record = {
            "masked": False,
            "sample_mode": "raw_secrets_redacted",
            "vulnerable_tables": [{
                "name": "profiles",
                "sample_data": [{
                    "email": "analyst@example.test",
                    "access_token": SECRET_REDACTION,
                }],
            }],
        }

        with patch.dict(os.environ, {"RAW_EVIDENCE_ENABLED": "true"}, clear=True):
            masked, masked_mode, available = _record_for_view(record, False)
            raw, raw_mode, _ = _record_for_view(record, True)

        self.assertTrue(available)
        self.assertEqual(masked_mode, "masked")
        self.assertNotEqual(
            masked["vulnerable_tables"][0]["sample_data"][0]["email"],
            "analyst@example.test",
        )
        self.assertEqual(raw_mode, "raw")
        self.assertEqual(
            raw["vulnerable_tables"][0]["sample_data"][0]["email"],
            "analyst@example.test",
        )

    def test_masked_storage_cannot_be_relabelled_as_raw(self):
        record = {
            "masked": True,
            "sample_mode": "masked",
            "vulnerable_tables": [{"sample_data": [{"email": "a••••"}]}],
        }

        with patch.dict(os.environ, {"RAW_EVIDENCE_ENABLED": "true"}, clear=True):
            rendered, mode, available = _record_for_view(record, True)

        self.assertFalse(available)
        self.assertEqual(mode, "masked")
        self.assertTrue(rendered["masked"])


class DiscoveryResilienceTests(unittest.TestCase):
    def test_one_failed_provider_does_not_discard_other_results(self):
        shodan_result = [{
            "url": "https://example.test/path",
            "source": "shodan",
            "metadata": {"query": "supabase"},
        }]

        with (
            patch("discovery._discover_shodan", AsyncMock(return_value=shodan_result)),
            patch(
                "discovery.commoncrawl_source.discover_targets",
                AsyncMock(side_effect=RuntimeError("temporary disconnect")),
            ),
            patch(
                "discovery.builtwith_source.discover_targets",
                AsyncMock(return_value=[]),
            ),
        ):
            targets = asyncio.run(
                discover_targets(["shodan", "commoncrawl", "builtwith"], 10)
            )

        self.assertEqual(list(targets), ["https://example.test"])
        self.assertEqual(targets["https://example.test"].sources, {"shodan"})


if __name__ == "__main__":
    unittest.main()
