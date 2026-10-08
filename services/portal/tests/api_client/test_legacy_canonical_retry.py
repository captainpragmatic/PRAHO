"""After an HMAC 401 over HTTPS, the client retries once with the legacy canonical signature.

A Platform still on the old canonical string rejects the new signature with an HMAC 401. The
client then re-signs exactly once with the legacy canonical form; any other 401, a plain-HTTP
Platform, or a second HMAC 401 gets no further retry.
"""

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient, PlatformAPIError


def _response(status: int, payload: dict[str, object]) -> Mock:
    response = Mock(status_code=status, headers={"Content-Type": "application/json"})
    response.json.return_value = payload
    response.text = ""
    return response


HMAC_401 = _response(401, {"error": "HMAC authentication failed"})
LOGIN_401 = _response(401, {"error": "Invalid credentials"})
OK = _response(200, {"success": True, "user": {"id": 7, "customer_id": 3}})


@override_settings(
    PLATFORM_API_TIMEOUT=5,
    PLATFORM_API_AUTH_MIN_DURATION_SECONDS=0,
    PORTAL_HMAC_SECRET="legacy-canonical-retry-secret",
    PORTAL_ID="portal-001",
)
class LegacyCanonicalRetryTests(SimpleTestCase):
    @contextmanager
    def platform(self, base_url: str, *responses: Mock) -> Iterator[tuple[Mock, Mock]]:
        with override_settings(PLATFORM_API_BASE_URL=base_url):
            client = PlatformAPIClient()
            with (
                patch("apps.api_client.services.portal_request", side_effect=list(responses)) as transport,
                patch.object(
                    client, "_prepare_legacy_request_headers", wraps=client._prepare_legacy_request_headers
                ) as legacy,
            ):
                self.client_under_test = client
                yield transport, legacy

    def login(self) -> dict[str, object] | None:
        return self.client_under_test.authenticate_customer("a@b.com", "pw")

    def test_an_hmac_401_over_https_is_retried_once_with_the_legacy_signature(self) -> None:
        with self.platform("https://platform.example.test/api", HMAC_401, OK) as (transport, legacy):
            result = self.login()
        self.assertIsNotNone(result)
        self.assertEqual(transport.call_count, 2)
        self.assertEqual(legacy.call_count, 1)

    def test_a_second_hmac_401_is_not_retried_again(self) -> None:
        with self.platform("https://platform.example.test/api", HMAC_401, HMAC_401) as (transport, legacy):
            self.assertIsNone(self.login())
        self.assertEqual((transport.call_count, legacy.call_count), (2, 1))

    def test_no_legacy_retry_for_a_wrong_password_or_plain_http(self) -> None:
        for name, base_url, first in (
            ("wrong password", "https://platform.example.test/api", LOGIN_401),
            ("plain http", "http://platform.example.test/api", HMAC_401),
        ):
            with self.subTest(case=name), self.platform(base_url, first, OK) as (transport, legacy):
                with suppress(PlatformAPIError):
                    self.login()
                self.assertEqual((transport.call_count, legacy.call_count), (1, 0))
