"""H9: HMAC rate limiter must deny requests when cache is unreachable."""
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.common.middleware import PortalServiceHMACMiddleware


class HMACRateLimiterFailClosedTests(SimpleTestCase):
    """H9: _rate_limited must return True (blocked) when cache is unreachable."""

    @patch("apps.common.middleware.cache")
    def test_cache_unreachable_denies_request(self, mock_cache):
        mock_cache.add.side_effect = ConnectionError("Redis down")
        mock_cache.incr.side_effect = ConnectionError("Redis down")
        mock_cache.get.side_effect = ConnectionError("Redis down")
        mock_cache.set.side_effect = ConnectionError("Redis down")

        mw = PortalServiceHMACMiddleware(lambda r: MagicMock(status_code=200))

        is_limited, wait_seconds = mw._rate_limited("portal-123", "10.0.0.1")
        self.assertTrue(is_limited, "Request must be rate-limited when cache is unreachable")
        self.assertGreater(wait_seconds, 0)
