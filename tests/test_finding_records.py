import json
import tempfile
import unittest
from pathlib import Path

from finding_records import serialize_evidence
from finding_store import load_latest_findings, matches_query, summarize_finding
from masking import SECRET_REDACTION, EvidenceConfig
from scan_models import Credential, ScanResult, SensitiveKeyExposure, TableResult


class FindingRecordTests(unittest.TestCase):
    def test_shared_serializer_never_persists_reusable_keys(self):
        public_key = "sb_publishable_" + "p" * 32
        secret_key = "sb_secret_" + "s" * 32
        result = ScanResult(
            target_url="https://example.test",
            credentials=[
                Credential(
                    supabase_url="https://project.supabase.co",
                    project_id="project",
                    anon_key=public_key,
                    source_file="fixture.js",
                )
            ],
            sensitive_key_exposures=[
                SensitiveKeyExposure(
                    key_type="sb_secret",
                    occurrence_count=1,
                    source_file="fixture.js",
                    fingerprint="0123456789abcdef",
                )
            ],
        )

        payload = json.dumps(
            serialize_evidence(
                result,
                EvidenceConfig(),
                include_tables_checked=True,
            )
        )

        self.assertNotIn(public_key, payload)
        self.assertNotIn(secret_key, payload)
        self.assertIn("0123456789abcdef", payload)

    def test_shared_serializer_keeps_raw_evidence_bounded_and_redacted(self):
        result = ScanResult(
            target_url="https://example.test",
            tables_checked=[
                TableResult(
                    name="profiles",
                    row_count=2,
                    rls_likely_disabled=True,
                    sample_data=[
                        {"email": "first@example.test", "access_token": "secret"},
                        {"email": "second@example.test", "access_token": "secret"},
                    ],
                )
            ],
        )

        record = serialize_evidence(
            result,
            EvidenceConfig(raw_values=True, sample_limit=1),
            include_tables_checked=True,
        )
        samples = record["vulnerable_tables"][0]["sample_data"]

        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]["email"], "first@example.test")
        self.assertEqual(samples[0]["access_token"], SECRET_REDACTION)


class FindingStoreTests(unittest.TestCase):
    def test_loader_keeps_latest_valid_record_per_target(self):
        older = {
            "target": "https://example.test",
            "timestamp": "2026-01-01T00:00:00Z",
            "vulnerable_tables": [],
        }
        newer = {
            "target": "https://example.test",
            "timestamp": "2026-02-01T00:00:00Z",
            "vulnerable_tables": [{"name": "public_profiles", "row_count": 2}],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            results_dir = Path(temp_dir)
            (results_dir / "findings_one.jsonl").write_text(
                "not-json\n" + json.dumps(older) + "\n",
                encoding="utf-8",
            )
            (results_dir / "findings_two.jsonl").write_text(
                json.dumps(newer) + "\n",
                encoding="utf-8",
            )

            findings = load_latest_findings(results_dir)

        self.assertEqual(findings, [newer])
        self.assertTrue(matches_query(newer, "profiles"))
        self.assertTrue(matches_query(newer, "EXAMPLE"))
        self.assertFalse(matches_query(newer, "orders"))
        self.assertEqual(summarize_finding(newer)["total_rows_exposed"], 2)

    def test_loader_handles_non_string_timestamps(self):
        malformed_timestamp = {
            "target": "https://example.test",
            "timestamp": 42,
        }
        newest = {
            "target": "https://example.test",
            "timestamp": "2026-10-24T13:00:00+00:00",
        }
        other = {
            "target": "https://other.test",
            "timestamp": "2026-10-24T12:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            results_dir = Path(temp_dir)
            (results_dir / "findings_test.jsonl").write_text(
                "\n".join(map(json.dumps, [malformed_timestamp, other, newest])),
                encoding="utf-8",
            )

            findings = load_latest_findings(results_dir)

        self.assertEqual(findings, [newest, other])

    def test_summary_tolerates_invalid_numeric_values(self):
        summary = summarize_finding(
            {
                "target": "https://example.test",
                "sensitive_key_exposures": [
                    {"occurrence_count": "many"},
                    {"occurrence_count": 2},
                ],
                "vulnerable_tables": [
                    {"name": "profiles", "row_count": "unknown"},
                    {"name": "orders", "row_count": 3},
                ],
            }
        )

        self.assertEqual(summary["sensitive_key_exposure_count"], 2)
        self.assertEqual(summary["total_rows_exposed"], 3)


if __name__ == "__main__":
    unittest.main()
