from __future__ import annotations

import time
from unittest.mock import patch

from django.contrib.sessions.middleware import SessionMiddleware
from django.test import SimpleTestCase
from django.test.client import RequestFactory

from apps.common.context_processors import portal_context
from apps.common.rate_limit_feedback import RATE_LIMIT_BANNER_UNTIL_KEY


def _request(path: str = "/dashboard/"):
    request = RequestFactory().get(path)
    middleware = SessionMiddleware(lambda r: None)
    middleware.process_request(request)
    return request


class PortalContextProcessorRateLimitTests(SimpleTestCase):
    @patch("apps.common.context_processors.get_account_health", return_value=None)
    def test_includes_rate_limit_banner_when_session_flag_exists(self, _mock_health) -> None:
        request = _request("/services/")
        request.session["customer_id"] = "1"
        request.session["user_id"] = "2"
        request.session[RATE_LIMIT_BANNER_UNTIL_KEY] = int(time.time()) + 15

        context = portal_context(request)

        self.assertIn("rate_limit_banner", context)
        self.assertEqual(context["rate_limit_banner"]["severity"], "warning")

    @patch("apps.common.context_processors.get_account_health", return_value=None)
    def test_no_rate_limit_banner_without_session_flag(self, _mock_health) -> None:
        request = _request("/services/")
        request.session["customer_id"] = "1"
        request.session["user_id"] = "2"

        context = portal_context(request)

        self.assertNotIn("rate_limit_banner", context)
