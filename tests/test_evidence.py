import base64
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from discovery import DiscoveryTarget
from discovery import _serialize_result as serialize_discovery
from main import ScanRequest, _record_for_view
from main import _serialize_result as serialize_api
from masking import (
    SECRET_REDACTION,
    EvidenceConfig,
    credential_preview,
    prepare_sample_data,
)
from scanner import Credential, ScanResult, TableResult


class EvidenceMaskingTests(unittest.TestCase):
    def test_raw_evidence_preserves_application_values_and_redacts_secrets(self):
        rows = [
            {
                "id": 42,
                "email": "analyst@example.test",
                "display_name": "Example Person",
                "access_token": "not-safe-to-display",
                "metadata": {
                    "city": "Amsterdam",
                    "password_hash": "also-not-safe",
                },
                "innocent_field": "eyJabcdefghijk.abcdefghijk.abcdefghijk",
            }
        ]

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

    def test_secret_key_matching_does_not_redact_unrelated_key_substrings(self):
        evidence = prepare_sample_data(
            [
                {
                    "monkey": "capuchin",
                    "api_key": "not-safe",
                    "refreshToken": "also-not-safe",
                }
            ],
            raw_values=True,
        )[0]

        self.assertEqual(evidence["monkey"], "capuchin")
        self.assertEqual(evidence["api_key"], SECRET_REDACTION)
        self.assertEqual(evidence["refreshToken"], SECRET_REDACTION)

    def test_evidence_config_defaults_to_masked_and_clamps_limit(self):
        with patch.dict(
            os.environ,
            {"RAW_EVIDENCE_ENABLED": "false", "RAW_EVIDENCE_SAMPLE_LIMIT": "99"},
            clear=True,
        ):
            config = EvidenceConfig.from_environment()

        self.assertFalse(config.raw_values)
        self.assertEqual(config.sample_limit, 3)

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
            record = serialize_discovery(
                result, DiscoveryTarget("https://example.test")
            )

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
            sample_data=[
                {
                    "email": "analyst@example.test",
                    "api_key": "not-safe-to-display",
                }
            ],
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
            record = serialize_discovery(
                result, DiscoveryTarget("https://example.test")
            )

        sample = record["vulnerable_tables"][0]["sample_data"][0]
        self.assertFalse(record["masked"])
        self.assertEqual(record["sample_mode"], "raw_secrets_redacted")
        self.assertEqual(sample["email"], "analyst@example.test")
        self.assertEqual(sample["api_key"], SECRET_REDACTION)

    def test_discovery_persists_only_a_non_reusable_key_preview(self):
        key = "eyJ" + "a" * 80
        result = ScanResult(
            target_url="https://example.test",
            credentials=[
                Credential(
                    supabase_url="https://project.supabase.co",
                    project_id="project",
                    anon_key=key,
                    source_file="fixture.js",
                )
            ],
        )

        with patch.dict(os.environ, {}, clear=True):
            record = serialize_discovery(
                result, DiscoveryTarget("https://example.test")
            )

        stored = record["credentials"][0]
        self.assertNotIn("anon_key", stored)
        self.assertEqual(stored["anon_key_preview"], credential_preview(key))
        self.assertNotIn(key, json.dumps(record))

    def test_api_requires_explicit_raw_request_even_when_enabled(self):
        result = ScanResult(
            target_url="https://example.test",
            tables_checked=[
                TableResult(
                    name="profiles",
                    row_count=1,
                    rls_likely_disabled=True,
                    sample_data=[
                        {
                            "email": "analyst@example.test",
                            "access_token": "not-safe",
                        }
                    ],
                )
            ],
        )

        with patch.dict(os.environ, {"RAW_EVIDENCE_ENABLED": "true"}, clear=True):
            masked = serialize_api(result)
            raw = serialize_api(result, raw_requested=True)

        self.assertEqual(masked.evidence_mode, "masked")
        self.assertNotEqual(
            masked.tables_checked[0].sample_data[0]["email"],
            "analyst@example.test",
        )
        self.assertEqual(raw.evidence_mode, "raw")
        self.assertEqual(
            raw.tables_checked[0].sample_data[0]["email"],
            "analyst@example.test",
        )
        self.assertEqual(
            raw.tables_checked[0].sample_data[0]["access_token"],
            SECRET_REDACTION,
        )

    def test_auth_cookie_parsing_does_not_leak_between_requests(self):
        payload = json.dumps(
            {
                "access_token": "access-token",
                "refresh_token": "r" * 200,
            }
        ).encode()
        blob = "base64-" + base64.urlsafe_b64encode(payload).decode().rstrip("=")

        first = ScanRequest(url="example.test", auth_token=blob)
        second = ScanRequest(url="example.test", auth_token="another-token")

        self.assertEqual(first.auth_token, "access-token")
        self.assertEqual(first.refresh_token, "r" * 200)
        self.assertEqual(second.auth_token, "another-token")
        self.assertIsNone(second.refresh_token)

    def test_browser_defaults_to_masked_and_requires_explicit_raw_request(self):
        record = {
            "masked": False,
            "sample_mode": "raw_secrets_redacted",
            "vulnerable_tables": [
                {
                    "name": "profiles",
                    "sample_data": [
                        {
                            "email": "analyst@example.test",
                            "access_token": SECRET_REDACTION,
                        }
                    ],
                }
            ],
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


if __name__ == "__main__":
    unittest.main()
