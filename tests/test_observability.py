import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path

from observability import (
    SafeJsonFormatter,
    normalize_request_id,
    read_status_file,
    redact_log_text,
    write_status_file,
)


class ObservabilityTests(unittest.TestCase):
    def test_log_redaction_removes_reusable_credentials(self):
        jwt = "eyJabcdefghijk.abcdefghijk.abcdefghijk"
        publishable = "sb_publishable_" + "a" * 32
        secret = "sb_secret_" + "s" * 32
        message = (
            f"Authorization: Bearer {jwt} apikey={publishable} secret={secret} "
            "https://example.test/path?access_token=plain-token&ok=1"
        )

        redacted = redact_log_text(message)

        self.assertNotIn(jwt, redacted)
        self.assertNotIn(publishable, redacted)
        self.assertNotIn(secret, redacted)
        self.assertNotIn("plain-token", redacted)
        self.assertIn("[redacted]", redacted)

    def test_json_formatter_redacts_message_and_traceback(self):
        secret = "sb_secret_" + "s" * 32
        try:
            raise RuntimeError(f"transport rejected {secret}")
        except RuntimeError:
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="failed with %s",
            args=(secret,),
            exc_info=exc_info,
        )
        record.component = "test"
        record.request_id = "req_12345678"
        record.operation_id = "scan_12345678"
        record.event = "synthetic_failure"

        rendered = SafeJsonFormatter().format(record)
        payload = json.loads(rendered)

        self.assertNotIn(secret, rendered)
        self.assertEqual(payload["event"], "synthetic_failure")
        self.assertIn("RuntimeError", payload["exception"])
        self.assertNotIn("transport rejected", payload["exception"])

    def test_status_file_round_trip_is_atomic_and_derived(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "diagnostics" / "status.json"
            value = {"run_id": "discovery_test", "status": "empty", "candidates": 0}

            write_status_file(path, value)

            self.assertEqual(read_status_file(path), value)
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_request_id_accepts_safe_values_and_replaces_unsafe_values(self):
        self.assertEqual(normalize_request_id("client-1234"), "client-1234")
        generated = normalize_request_id("bad id with spaces")
        self.assertTrue(generated.startswith("req_"))
        self.assertNotIn(" ", generated)


if __name__ == "__main__":
    unittest.main()
