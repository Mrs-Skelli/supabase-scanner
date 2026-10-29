"""Checks for the public install path and analyst-only API boundary."""

import json
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from cli import main as cli_main
from main import app


class PublicInterfaceTests(unittest.TestCase):
    def test_cli_requires_explicit_authorization_before_network_use(self):
        with patch("cli.scan") as scan:
            with self.assertRaises(SystemExit) as error:
                cli_main(["https://example.test"])
        self.assertEqual(error.exception.code, 2)
        scan.assert_not_called()

    def test_sensitive_api_fails_closed_and_accepts_configured_analyst(self):
        with TestClient(app) as client:
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(client.get("/api/diagnostics").status_code, 503)
            with patch.dict(
                os.environ,
                {"ANALYST_USERNAME": "analyst", "ANALYST_PASSWORD": "test-password"},
            ):
                denied = client.get("/api/diagnostics")
                self.assertEqual(denied.status_code, 401)
                self.assertEqual(denied.headers["www-authenticate"], "Basic")
                allowed = client.get(
                    "/api/diagnostics", auth=("analyst", "test-password")
                )
                self.assertEqual(allowed.status_code, 200)
                self.assertEqual(
                    json.loads(allowed.text)["service"], "supabase-scanner"
                )

    def test_public_masked_browser_remains_available(self):
        with TestClient(app) as client:
            self.assertEqual(client.get("/browse").status_code, 200)
            self.assertEqual(client.get("/api/findings?limit=1").status_code, 200)
