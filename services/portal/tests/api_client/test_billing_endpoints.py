"""The portal reaches Platform's payment endpoints under /api/billing/, on any base URL."""

from unittest.mock import patch

import requests
from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient


def _ok() -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"success": true}'
    response.headers["Content-Type"] = "application/json"
    return response


class BillingEndpointURLTests(SimpleTestCase):
    def test_payment_calls_go_to_api_billing_without_touching_the_base_url(self) -> None:
        # The helpers used to strip "/api" with str.replace, which turned
        # "https://api.example.com/api" into "https:/.example.com", and changed
        # self.base_url for the duration of the call.
        cases = (
            ("https://api.example.com/api", "https://api.example.com/api/billing/"),
            ("http://platform:8700/api", "http://platform:8700/api/billing/"),
            ("https://platform.example.com/api/", "https://platform.example.com/api/billing/"),
            ("https://platform.example.com", "https://platform.example.com/api/billing/"),
        )
        for base_url, expected_prefix in cases:
            with (
                self.subTest(base_url=base_url),
                override_settings(PLATFORM_API_BASE_URL=base_url, PLATFORM_API_ALLOW_INSECURE_HTTP=True),
                patch("apps.api_client.services.portal_request", return_value=_ok()) as transport,
            ):
                client = PlatformAPIClient()
                client.post_billing("create-payment-intent/", data={"order_id": "o-1"})
                client.get_billing("stripe-config/")
                urls = [call.kwargs["url"] for call in transport.call_args_list]
                self.assertEqual(
                    urls,
                    [f"{expected_prefix}create-payment-intent/", f"{expected_prefix}stripe-config/"],
                )
                self.assertEqual(client.base_url, base_url)

    def test_the_staff_page_helpers_are_gone(self) -> None:
        # get_invoices / get_invoice_detail routed to Platform's /billing/invoices/ staff pages.
        self.assertFalse(hasattr(PlatformAPIClient, "get_invoices"))
        self.assertFalse(hasattr(PlatformAPIClient, "get_invoice_detail"))
