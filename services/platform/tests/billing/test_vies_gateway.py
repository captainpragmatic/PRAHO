"""Tests for VIES gateway (apps.billing.gateways.vies_gateway)."""

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.billing.gateways.vies_gateway import VIESGateway, VIESResponse


class TestVIESResponse(SimpleTestCase):
    """Test VIESResponse dataclass defaults."""

    def test_defaults(self):
        r = VIESResponse(is_valid=True, country_code="DE", vat_number="123456789")
        self.assertTrue(r.is_valid)
        self.assertTrue(r.api_available)
        self.assertEqual(r.company_name, "")
        self.assertEqual(r.error_message, "")
        self.assertEqual(r.raw_response, {})


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestVIESGateway(SimpleTestCase):
    """Test VIESGateway.check_vat() with mocked HTTP."""

    @patch("apps.billing.gateways.vies_gateway.safe_request")
    def test_valid_vat_returns_valid_response(self, mock_request):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "isValid": True,
            "countryCode": "DE",
            "vatNumber": "123456789",
            "name": "Test GmbH",
            "address": "Berlin, Germany",
            "requestDate": "2026-03-10",
        }
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        result = VIESGateway.check_vat("DE", "123456789")

        self.assertTrue(result.is_valid)
        self.assertTrue(result.api_available)
        self.assertEqual(result.company_name, "Test GmbH")
        self.assertEqual(result.company_address, "Berlin, Germany")
        mock_request.assert_called_once()

    @patch("apps.billing.gateways.vies_gateway.safe_request")
    def test_invalid_vat_returns_invalid_response(self, mock_request):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "isValid": False,
            "countryCode": "DE",
            "vatNumber": "000000000",
        }
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        result = VIESGateway.check_vat("DE", "000000000")

        self.assertFalse(result.is_valid)
        self.assertTrue(result.api_available)

    @patch("apps.billing.gateways.vies_gateway.safe_request")
    def test_api_error_returns_unavailable(self, mock_request):
        mock_request.side_effect = ConnectionError("VIES is down")

        result = VIESGateway.check_vat("DE", "123456789")

        self.assertFalse(result.is_valid)
        self.assertFalse(result.api_available)
        # Generic message hides infrastructure details (M6 fix — don't leak IPs/DNS)
        self.assertIn("temporarily unavailable", result.error_message)

    @patch("apps.billing.gateways.vies_gateway.cache")
    @patch("apps.billing.gateways.vies_gateway.safe_request")
    def test_cache_hit_skips_api_call(self, mock_request, mock_cache):
        cached = {
            "is_valid": True, "country_code": "FR", "vat_number": "12345678901",
            "company_name": "Cached Co", "api_available": True,
            "company_address": "", "request_date": "", "error_message": "",
            "raw_response": {},
        }
        mock_cache.get.return_value = cached

        result = VIESGateway.check_vat("FR", "12345678901")

        self.assertTrue(result.is_valid)
        self.assertEqual(result.company_name, "Cached Co")
        mock_request.assert_not_called()
