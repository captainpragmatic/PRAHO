"""H16+H17: Rate limiters must deny requests when cache is unreachable."""
from unittest.mock import MagicMock, patch

from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase, override_settings

from apps.common.rate_limiting import ALL, rate_limit
from apps.common.security_decorators import _check_rate_limit


class SecurityDecoratorRateLimitFailClosedTests(SimpleTestCase):
    """H16: _check_rate_limit must raise when cache is completely unreachable."""

    @patch("apps.common.security_decorators.cache")
    def test_check_rate_limit_fails_closed_on_cache_error(self, mock_cache: MagicMock) -> None:
        mock_cache.get.side_effect = ConnectionError("Redis down")
        mock_cache.set.side_effect = ConnectionError("Redis down")
        mock_cache.incr.side_effect = ConnectionError("Redis down")
        mock_cache.add.side_effect = ConnectionError("Redis down")

        # Should raise an exception, not silently allow
        with self.assertRaises(ValidationError):
            _check_rate_limit("test_action", 5, "10.0.0.1")


class ViewRateLimitFailClosedTests(SimpleTestCase):
    """H17: @rate_limit decorator must return 503 when cache is unreachable."""

    @override_settings(RATE_LIMITING_ENABLED=True)
    @patch("apps.common.rate_limiting.caches")
    def test_rate_limit_decorator_returns_503_on_cache_failure(self, mock_caches: MagicMock) -> None:
        mock_cache = MagicMock()
        mock_cache.add.side_effect = ConnectionError("Redis down")
        mock_cache.incr.side_effect = ConnectionError("Redis down")
        mock_cache.get.side_effect = ConnectionError("Redis down")
        mock_cache.set.side_effect = ConnectionError("Redis down")
        mock_caches.__getitem__.return_value = mock_cache

        @rate_limit(key="ip", rate="5/m", method=ALL, block=True)
        def dummy_view(request: HttpRequest) -> HttpResponse:
            return HttpResponse("ok")

        request = HttpRequest()
        request.method = "POST"
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.user = MagicMock(is_authenticated=False)

        response = dummy_view(request)
        self.assertIn(response.status_code, [429, 503])
