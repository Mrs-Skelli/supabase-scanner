import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

import wayback_source


class WaybackTests(unittest.IsolatedAsyncioTestCase):
    def test_snapshot_url_is_archive_only_and_uses_raw_replay(self):
        self.assertEqual(
            wayback_source._snapshot_replay_url(
                "http://web.archive.org/web/20200102030405/https://example.test/"
            ),
            "https://web.archive.org/web/20200102030405id_/https://example.test/",
        )
        self.assertIsNone(
            wayback_source._snapshot_replay_url(
                "https://attacker.example/web/20200102030405/https://example.test/"
            )
        )

    async def test_enrichment_extracts_historical_metadata_without_raw_keys(self):
        publishable = "sb_publishable_" + "p" * 24
        secret = "sb_secret_" + "s" * 24

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "archive.org":
                requested = request.url.params.get("url")
                if requested == "https://example.test":
                    capture = (
                        "http://web.archive.org/web/20200102030405/"
                        "https://example.test/"
                    )
                else:
                    capture = (
                        "http://web.archive.org/web/20200102030405/"
                        "https://example.test/app.js"
                    )
                return httpx.Response(
                    200,
                    json={
                        "archived_snapshots": {
                            "closest": {
                                "available": True,
                                "url": capture,
                                "timestamp": "20200102030405",
                                "status": "200",
                            }
                        }
                    },
                )
            if request.url.path.endswith("https://example.test/"):
                return httpx.Response(
                    200,
                    text=(
                        '<script src="/app.js"></script>'
                        f'<script>createClient("https://abc.supabase.co", '
                        f'"{publishable}")</script>'
                    ),
                )
            return httpx.Response(200, text=f'const leaked = "{secret}";')

        mock_client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        )
        with (
            patch(
                "wayback_source.httpx.AsyncClient",
                return_value=mock_client,
            ),
            patch("wayback_source.asyncio.sleep", AsyncMock()),
        ):
            result = await wayback_source.enrich_target("https://example.test")

        serialized = json.dumps(result)
        self.assertEqual(result["status"], "archived")
        self.assertTrue(result["historical_only"])
        self.assertEqual(result["assets_checked"], 2)
        self.assertEqual(result["project_configs"][0]["project_id"], "abc")
        self.assertEqual(
            set(result["key_types"]),
            {"sb_publishable", "sb_secret"},
        )
        self.assertEqual(
            result["sensitive_key_exposures"][0]["key_type"],
            "sb_secret",
        )
        self.assertNotIn(publishable, serialized)
        self.assertNotIn(secret, serialized)

    async def test_missing_capture_is_reported_without_fetching_target(self):
        requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"archived_snapshots": {}})

        with patch(
            "wayback_source.httpx.AsyncClient",
            return_value=httpx.AsyncClient(
                transport=httpx.MockTransport(handler),
                follow_redirects=False,
            ),
        ):
            result = await wayback_source.enrich_target("https://example.test")

        self.assertEqual(result["status"], "not_archived")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url.host, "archive.org")


if __name__ == "__main__":
    unittest.main()
