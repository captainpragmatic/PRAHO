"""The e-Factura client counts total attempts, including its first request."""

from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import TestCase

from apps.billing.efactura.client import EFacturaClient, EFacturaConfig, NetworkError
from tests.helpers.legacy_settings import store_legacy_integer


class NonpositiveEFacturaAttemptTests(TestCase):
    def test_legacy_nonpositive_attempts_return_the_healthy_response(self) -> None:
        self.addCleanup(cache.clear)
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"accepted": true}'
        for stored in (0, -1, 1):
            with self.subTest(stored=stored):
                store_legacy_integer("billing.efactura_api_max_retries", stored)
                cache.clear()
                client = EFacturaClient(EFacturaConfig.from_settings())
                with patch("apps.billing.efactura.client.safe_request", return_value=response):
                    try:
                        result = client._request_with_retry("GET", "https://api.anaf.ro/test/stareMesaj")
                    except NetworkError:
                        self.fail("a legacy nonpositive attempt budget must still send the initial fiscal request")
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json(), {"accepted": True})
