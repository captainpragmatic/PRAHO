"""Contract tests for Platform login response identity mapping."""

from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient


@override_settings(
    DEBUG=True,
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_TIMEOUT=5,
    PLATFORM_API_AUTH_MIN_DURATION_SECONDS=0,
    PORTAL_HMAC_SECRET="authenticate-customer-contract-secret",
    PORTAL_ID="portal-001",
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "authenticate-customer-contract",
        }
    },
)
class AuthenticateCustomerContractTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.api_client = PlatformAPIClient()

    def test_success_without_user_object_is_not_a_login(self) -> None:
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"success": True}
        headers = {
            "X-Portal-Id": "portal-001",
            "X-Signature": "a" * 64,
            "X-Nonce": "n" * 16,
            "X-Timestamp": "1700000000",
            "X-Body-Hash": "a" * 43 + "=",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        with (
            patch("apps.api_client.services.portal_request", return_value=response),
            patch.object(self.api_client, "_generate_hmac_headers", return_value=headers),
        ):
            result = self.api_client.authenticate_customer("a@b.com", "pw")

        self.assertIsNone(result)

    def test_success_with_user_object_maps_identity(self) -> None:
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"success": True, "user": {"id": 7, "customer_id": 3}}

        with patch("apps.api_client.services.portal_request", return_value=response):
            result = self.api_client.authenticate_customer("a@b.com", "pw")

        self.assertEqual(
            result,
            {
                "valid": True,
                "token": 7,
                "user_id": 7,
                "customer_id": 3,
                "customer_data": {"id": 7, "customer_id": 3},
            },
        )
