import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

import commoncrawl_source


class CommonCrawlTests(unittest.IsolatedAsyncioTestCase):
    async def test_index_catalogue_retries_transient_failure(self):
        calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(503, text="busy")
            return httpx.Response(
                200,
                json=[{"cdx-api": "https://index.example.test/crawl-index"}],
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with patch("commoncrawl_source.asyncio.sleep", AsyncMock()) as delay:
                indexes = await commoncrawl_source._get_recent_indexes(client, 1)

        self.assertEqual(calls, 2)
        self.assertEqual(indexes, ["https://index.example.test/crawl-index"])
        delay.assert_awaited_once()

    async def test_index_query_paginates_until_limit(self):
        pages_seen: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            page = request.url.params["page"]
            pages_seen.append(page)
            start = int(page) * 2
            records = [
                {"url": f"https://example.test/{start + offset}"} for offset in range(2)
            ]
            return httpx.Response(
                200,
                text="\n".join(json.dumps(record) for record in records),
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with (
                patch("commoncrawl_source.MAX_INDEX_PAGE_RESULTS", 2),
                patch("commoncrawl_source.asyncio.sleep", AsyncMock()),
            ):
                records = await commoncrawl_source._query_index(
                    client,
                    "https://index.example.test/crawl-index",
                    "*supabase*",
                    3,
                )

        self.assertEqual(pages_seen, ["0", "1"])
        self.assertEqual(len(records), 3)

    async def test_index_query_retries_transient_failure(self):
        calls = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(503, text="busy")
            return httpx.Response(
                200,
                text=json.dumps({"url": "https://example.test/app.js"}),
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with patch("commoncrawl_source.asyncio.sleep", AsyncMock()) as delay:
                records = await commoncrawl_source._query_index(
                    client,
                    "https://index.example.test/crawl-index",
                    "*supabase*",
                    1,
                )

        self.assertEqual(calls, 2)
        self.assertEqual(len(records), 1)
        delay.assert_awaited_once()

    async def test_exhausted_index_query_is_a_provider_failure_signal(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="busy")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with patch("commoncrawl_source.asyncio.sleep", AsyncMock()):
                with self.assertRaises(commoncrawl_source.CommonCrawlQueryUnavailable):
                    await commoncrawl_source._query_index(
                        client,
                        "https://index.example.test/crawl-index",
                        "*supabase*",
                        1,
                    )

    async def test_modern_config_marker_discovers_custom_domain(self):
        record = {
            "url": "https://app.example.test/assets/supabase-client.js",
            "filename": "segment.warc.gz",
            "offset": "0",
            "length": "1",
        }
        body = (
            'const VITE_SUPABASE_URL="https://api.example.test";'
            'const VITE_SUPABASE_PUBLISHABLE_KEY="sb_publishable_fixture";'
        )
        with (
            patch(
                "commoncrawl_source._get_recent_indexes",
                AsyncMock(return_value=["https://index.example.test/crawl-index"]),
            ),
            patch(
                "commoncrawl_source._query_index",
                AsyncMock(return_value=[record]),
            ),
            patch(
                "commoncrawl_source._fetch_warc_body",
                AsyncMock(return_value=body),
            ),
        ):
            results = await commoncrawl_source.discover_targets(
                max_results=1,
                recent_indexes=1,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["url"], "https://app.example.test")
        self.assertEqual(results[0]["source"], "commoncrawl")
        self.assertEqual(results[0]["metadata"]["confidence"], "high")
        self.assertIn(
            "vite_supabase_url",
            results[0]["metadata"]["signals"],
        )

    async def test_oversized_warc_record_is_not_fetched(self):
        client = AsyncMock()
        body = await commoncrawl_source._fetch_warc_body(
            client,
            {
                "filename": "segment.warc.gz",
                "offset": "0",
                "length": str(commoncrawl_source.MAX_WARC_RECORD_SIZE + 1),
            },
        )

        self.assertIsNone(body)
        client.get.assert_not_awaited()

    async def test_malformed_warc_range_is_not_fetched(self):
        client = AsyncMock()
        body = await commoncrawl_source._fetch_warc_body(
            client,
            {
                "filename": "segment.warc.gz",
                "offset": "not-a-number",
                "length": "10",
            },
        )

        self.assertIsNone(body)
        client.get.assert_not_awaited()

    async def test_all_index_query_failures_fail_the_provider(self):
        with (
            patch(
                "commoncrawl_source._get_recent_indexes",
                AsyncMock(return_value=["https://index.example.test/crawl-index"]),
            ),
            patch(
                "commoncrawl_source._query_index",
                AsyncMock(
                    side_effect=commoncrawl_source.CommonCrawlQueryUnavailable(
                        "unavailable"
                    )
                ),
            ),
            patch("commoncrawl_source.COMMONCRAWL_QUERY_PATTERNS", ["*supabase*"]),
        ):
            with self.assertRaises(commoncrawl_source.CommonCrawlUnavailable):
                await commoncrawl_source.discover_targets(max_results=1)


if __name__ == "__main__":
    unittest.main()
