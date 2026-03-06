from __future__ import annotations

from unittest.mock import patch

from django.contrib.sessions.middleware import SessionMiddleware
from django.test import SimpleTestCase
from django.test.client import RequestFactory

from apps.common.context_processors import portal_context


def _request(path: str = "/dashboard/"):
    request = RequestFactory().get(path)
    middleware = SessionMiddleware(lambda r: None)
    middleware.process_request(request)
    return request


class PortalContextProcessorRateLimitTests(SimpleTestCase):
    @patch("apps.common.context_processors.get_account_health", return_value=None)
    def test_context_processor_does_not_set_rate_limit_keys(self, _mock_health) -> None:
        """Rate-limit feedback uses Django messages, not context processor keys."""
        request = _request("/services/")
        request.session["customer_id"] = "1"
        request.session["user_id"] = "2"

        context = portal_context(request)

        self.assertNotIn("rate_limit_banner", context)
        self.assertNotIn("rate_limited", context)
