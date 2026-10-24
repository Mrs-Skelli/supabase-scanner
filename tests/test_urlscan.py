import os
import unittest
from unittest.mock import AsyncMock, patch

import httpx

import urlscan_source


class URLScanTests(unittest.IsolatedAsyncioTestCase):
    def test_origin_normalization_removes_userinfo_path_and_query(self):
        self.assertEqual(
            urlscan_source._normalize_origin(
                "https://user:secret@App.Example.test:8443/path?token=secret"
            ),
            "https://app.example.test:8443",
        )

    async def test_discovery_paginates_deduplicates_and_uses_api_key_header(self):
        requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if "search_after" not in request.url.params:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {
                                "task": {"url": "https://app.example.test/one"},
                                "sort": ["2026-10-24", "one"],
                            }
                        ],
                        "has_more": True,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "page": {"url": "https://app.example.test/two"},
                            "sort": ["2026-10-23", "two"],
                        }
                    ],
                    "has_more": False,
                },
            )

        mock_client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=True,
        )
        with (
            patch.dict(os.environ, {"URLSCAN_API_KEY": "synthetic-key"}, clear=True),
            patch("urlscan_source.URLSCAN_QUERIES", (("hosted", "domain:test"),)),
            patch("urlscan_source.URLSCAN_PAGE_SIZE", 1),
            patch("urlscan_source.asyncio.sleep", AsyncMock()),
            patch(
                "urlscan_source.httpx.AsyncClient",
                return_value=mock_client,
            ) as client_factory,
        ):
            results = await urlscan_source.discover_targets(
                max_results=2,
                per_query_limit=2,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["url"], "https://app.example.test")
        self.assertEqual(results[0]["matches"], 2)
        self.assertEqual(len(requests), 2)
        self.assertEqual(
            client_factory.call_args.kwargs["headers"]["api-key"],
            "synthetic-key",
        )
        self.assertEqual(requests[1].url.params["search_after"], "2026-10-24,one")

    async def test_all_query_failures_raise_safe_provider_error(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="sensitive upstream detail")

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("urlscan_source.URLSCAN_QUERIES", (("hosted", "domain:test"),)),
            patch("urlscan_source.asyncio.sleep", AsyncMock()),
            patch(
                "urlscan_source.httpx.AsyncClient",
                return_value=httpx.AsyncClient(
                    transport=httpx.MockTransport(handler),
                    follow_redirects=True,
                ),
            ),
            self.assertLogs("urlscan_source", level="WARNING") as logs,
        ):
            with self.assertRaises(urlscan_source.URLScanUnavailable):
                await urlscan_source.discover_targets(max_results=1)

        self.assertNotIn("sensitive upstream detail", " ".join(logs.output))


if __name__ == "__main__":
    unittest.main()
