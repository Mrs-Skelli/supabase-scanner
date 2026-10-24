import base64
import json
import unittest
from unittest.mock import patch

import httpx

from scanner import (
    Credential,
    _check_table_rls,
    _extract_js_urls,
    _extract_table_names_from_js,
    _find_credentials,
    _parse_content_range,
    _source_label,
)
from ssrf_guard import validate_url


class ScannerParsingTests(unittest.TestCase):
    publishable_key = "sb_publishable_" + "a" * 32
    secret_key = "sb_secret_" + "s" * 32

    def test_content_range_parser(self):
        self.assertEqual(_parse_content_range("0-0/42"), 42)
        self.assertIsNone(_parse_content_range("*/ *"))
        self.assertIsNone(_parse_content_range(None))

    def test_table_extraction_filters_javascript_builtins(self):
        source = 'client.from("profiles"); value.from("prototype")'

        self.assertEqual(_extract_table_names_from_js(source), {"profiles"})

    def test_javascript_url_extraction_handles_bundler_preloads(self):
        html = """
        <script src="/assets/app.js"></script>
        <link rel="modulepreload" href="chunks/vendor.js">
        <script src="data:text/javascript,ignored"></script>
        """

        self.assertEqual(
            _extract_js_urls(html, "https://example.test/path/"),
            [
                "https://example.test/assets/app.js",
                "https://example.test/path/chunks/vendor.js",
            ],
        )

    def test_ssrf_guard_rejects_embedded_credentials_before_dns(self):
        self.assertEqual(
            validate_url("https://user:password@example.test/path"),
            "embedded URL credentials are not allowed",
        )

    def test_ssrf_guard_rejects_invalid_ports(self):
        self.assertEqual(
            validate_url("https://example.test:not-a-port"),
            "invalid port",
        )

    def test_source_labels_do_not_persist_query_secrets_or_userinfo(self):
        label = _source_label(
            "https://user:password@example.test/app.js?token=secret#fragment"
        )

        self.assertEqual(label, "https://example.test/app.js")

    def test_hosted_publishable_key_is_recognized(self):
        source = (
            'const url = "https://project-ref.supabase.co";'
            f'const key = "{self.publishable_key}";'
        )

        with patch("scanner.validate_url", return_value=None):
            credentials = _find_credentials(source, "fixture.js")

        self.assertEqual(len(credentials), 1)
        self.assertEqual(credentials[0].project_id, "project-ref")
        self.assertEqual(credentials[0].anon_key, self.publishable_key)

    def test_create_client_pair_recognizes_custom_domain(self):
        source = (
            'const client = createClient("https://data.example.test/supabase", '
            f'"{self.publishable_key}");'
        )

        with patch("scanner.validate_url", return_value=None):
            credentials = _find_credentials(source, "fixture.js")

        self.assertEqual(len(credentials), 1)
        self.assertEqual(
            credentials[0].supabase_url,
            "https://data.example.test/supabase",
        )
        self.assertEqual(credentials[0].project_id, "data.example.test")

    def test_named_config_pair_recognizes_custom_domain(self):
        source = (
            'const supabaseUrl = "https://db.example.test";'
            f'const supabaseKey = "{self.publishable_key}";'
        )

        with patch("scanner.validate_url", return_value=None):
            credentials = _find_credentials(source, "fixture.js")

        self.assertEqual(len(credentials), 1)
        self.assertEqual(credentials[0].supabase_url, "https://db.example.test")

    def test_unpaired_custom_domain_is_not_treated_as_supabase(self):
        source = (
            'const endpoint = "https://api.example.test";'
            f'const unrelated = "{self.publishable_key}";'
        )

        with patch("scanner.validate_url", return_value=None):
            credentials = _find_credentials(source, "fixture.js")

        self.assertEqual(credentials, [])

    def test_secret_key_is_detected_but_never_returned(self):
        source = (
            'const leaked = createClient("https://project-ref.supabase.co", '
            f'"{self.secret_key}");'
        )

        with (
            patch("scanner.validate_url", return_value=None),
            self.assertLogs("scanner", level="WARNING") as logs,
        ):
            credentials = _find_credentials(source, "fixture.js")

        self.assertEqual(credentials, [])
        self.assertNotIn(self.secret_key, " ".join(logs.output))

    def test_legacy_service_role_jwt_is_never_returned(self):
        payload = (
            base64.urlsafe_b64encode(json.dumps({"role": "service_role"}).encode())
            .decode()
            .rstrip("=")
        )
        service_role_key = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + payload + "." + "a" * 32
        )
        source = (
            'const url = "https://project-ref.supabase.co";'
            f'const key = "{service_role_key}";'
        )

        with patch("scanner.validate_url", return_value=None):
            credentials = _find_credentials(source, "fixture.js")

        self.assertEqual(credentials, [])


class TableCheckTests(unittest.IsolatedAsyncioTestCase):
    credential = Credential(
        supabase_url="https://project.supabase.co",
        project_id="project",
        anon_key="synthetic-anon-key",
        source_file="fixture.js",
    )

    async def test_table_check_uses_bounded_read_and_exact_count(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.params["limit"], "1")
            self.assertEqual(request.headers["prefer"], "count=exact")
            return httpx.Response(
                200,
                headers={"content-range": "0-0/42"},
                json=[{"id": 1, "email": "analyst@example.test"}],
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await _check_table_rls(client, self.credential, "profiles")

        self.assertTrue(result.rls_likely_disabled)
        self.assertEqual(result.row_count, 42)
        self.assertEqual(result.sample_columns, ["id", "email"])
        self.assertEqual(len(result.sample_data), 1)

    async def test_table_check_does_not_return_transport_details(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("sensitive internal detail", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await _check_table_rls(client, self.credential, "profiles")

        self.assertEqual(result.error, "request failed (ConnectError)")
        self.assertNotIn("sensitive", result.error)


if __name__ == "__main__":
    unittest.main()
