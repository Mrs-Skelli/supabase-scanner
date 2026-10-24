import unittest
from unittest.mock import AsyncMock, patch

from discovery import discover_targets


class DiscoveryResilienceTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_provider_does_not_discard_other_results(self):
        shodan_result = [
            {
                "url": "https://example.test/path",
                "source": "shodan",
                "metadata": {"query": "supabase"},
            }
        ]

        with (
            patch(
                "discovery._discover_shodan",
                AsyncMock(return_value=shodan_result),
            ),
            patch(
                "discovery.commoncrawl_source.discover_targets",
                AsyncMock(side_effect=RuntimeError("temporary disconnect")),
            ),
            patch(
                "discovery.builtwith_source.discover_targets",
                AsyncMock(return_value=[]),
            ),
        ):
            targets = await discover_targets(["shodan", "commoncrawl", "builtwith"], 10)

        self.assertEqual(list(targets), ["https://example.test"])
        self.assertEqual(targets["https://example.test"].sources, {"shodan"})


if __name__ == "__main__":
    unittest.main()
