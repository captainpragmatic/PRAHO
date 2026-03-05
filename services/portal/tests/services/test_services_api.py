from __future__ import annotations

from unittest.mock import patch

from django.test import SimpleTestCase

from apps.api_client.services import PlatformAPIError
from apps.services.services import ServicesAPIClient


class ServicesAPIClientRateLimitTests(SimpleTestCase):
    @patch("apps.services.services.ServicesAPIClient._make_request")
    def test_get_services_summary_reraises_rate_limit_error(self, mock_make_request) -> None:
        mock_make_request.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=8, is_rate_limited=True
        )
        client = ServicesAPIClient()

        with self.assertRaises(PlatformAPIError):
            client.get_services_summary(customer_id=1, user_id=2)
