import os
import unittest
from unittest.mock import patch

import httpx

import builtwith_source


class BuiltWithTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_key_is_an_explicit_disabled_result(self):
        with patch.dict(os.environ, {}, clear=True):
            results = await builtwith_source.discover_targets(max_results=1)

        self.assertEqual(results, [])

    async def test_first_request_failure_is_not_reported_as_empty_success(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="signed request detail")

        with (
            patch.dict(os.environ, {"BUILTWITH_API_KEY": "synthetic-key"}),
            patch(
                "builtwith_source.httpx.AsyncClient",
                return_value=httpx.AsyncClient(
                    transport=httpx.MockTransport(handler),
                    follow_redirects=True,
                ),
            ),
            self.assertLogs("builtwith_source", level="WARNING") as logs,
        ):
            with self.assertRaises(builtwith_source.BuiltWithUnavailable):
                await builtwith_source.discover_targets(max_results=1)

        output = " ".join(logs.output)
        self.assertIn("BuiltWith request failed", output)
        self.assertNotIn("signed request detail", output)
        self.assertNotIn("synthetic-key", output)

    def test_domain_normalization_rejects_non_string_values(self):
        self.assertIsNone(builtwith_source._normalize_domain({"bad": "value"}))


if __name__ == "__main__":
    unittest.main()
