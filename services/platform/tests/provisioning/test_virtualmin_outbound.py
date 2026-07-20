"""Tests for Virtualmin gateway migration to safe_request()."""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import MagicMock, patch

from django.core.cache import cache as django_cache
from django.test import TestCase, override_settings

from apps.provisioning.virtualmin_gateway import (
    RateLimitOutcome,
    VirtualminAPIError,
    VirtualminConfig,
    VirtualminGateway,
)


class VirtualminOutboundTests(TestCase):
    """Verify Virtualmin gateway uses safe_request() with DNS pinning."""

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    def test_execute_http_request_routes_through_safe_request_with_pinning_policy(
        self, mock_safe_request: MagicMock
    ) -> None:
        """_execute_http_request must actually call safe_request with an
        https-only, pin-carrying policy — not merely exist."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-length": "20"}
        mock_response.iter_content.return_value = iter([b'{"status":"success"}'])
        mock_safe_request.return_value = mock_response

        gateway = self._gateway(fingerprint="a" * 64)
        gateway._execute_http_request({"program": "list-domains"})

        self.assertEqual(mock_safe_request.call_count, 1)
        policy = mock_safe_request.call_args.kwargs["policy"]
        self.assertTrue(policy.require_https)
        self.assertEqual(policy.allowed_schemes, frozenset({"https"}))
        self.assertEqual(policy.tls_cert_fingerprint, "a" * 64)

    def _gateway(
        self,
        *,
        api_url: str = "https://virtualmin.example.com:10000/remote.cgi",
        use_ssl: bool = True,
        verify_ssl: bool = True,
        fingerprint: str = "",
    ) -> VirtualminGateway:
        server = MagicMock()
        server.hostname = "virtualmin.example.com"
        server.api_url = api_url
        server.api_username = "praho-api"
        server.use_ssl = use_ssl
        server.ssl_cert_fingerprint = fingerprint
        server.get_api_password.return_value = "secret"
        return VirtualminGateway(
            VirtualminConfig(
                server=server,
                verify_ssl=verify_ssl,
                cert_fingerprint=fingerprint,
                use_credential_vault=False,
            )
        )

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    def test_http_is_rejected_before_credentials_are_read(self, mock_safe_request: MagicMock) -> None:
        gateway = self._gateway(api_url="http://virtualmin.example.com:10000/remote.cgi", use_ssl=False)
        gateway.server.get_api_password.side_effect = AssertionError("credentials must not be read")

        with self.assertRaises(VirtualminAPIError):
            gateway._execute_http_request({"program": "info"})

        mock_safe_request.assert_not_called()

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    def test_disabled_ca_verification_requires_certificate_fingerprint(self, mock_safe_request: MagicMock) -> None:
        gateway = self._gateway(verify_ssl=False)

        with self.assertRaises(VirtualminAPIError):
            gateway._execute_http_request({"program": "info"})

        mock_safe_request.assert_not_called()

    @patch("apps.provisioning.virtualmin_gateway.safe_request")
    def test_fingerprint_is_enforced_by_outbound_transport(self, mock_safe_request: MagicMock) -> None:
        fingerprint = "ab" * 32
        gateway = self._gateway(verify_ssl=False, fingerprint=fingerprint)
        mock_safe_request.return_value = MagicMock()

        gateway._execute_http_request({"program": "info"})

        policy = mock_safe_request.call_args.kwargs["policy"]
        self.assertTrue(policy.require_https)
        self.assertEqual(policy.allowed_schemes, frozenset({"https"}))
        self.assertEqual(policy.tls_cert_fingerprint, fingerprint)

    @patch("apps.provisioning.virtualmin_gateway.cache")
    def test_rate_limit_claims_slots_with_atomic_cache_add(self, mock_cache: MagicMock) -> None:
        gateway = self._gateway()
        mock_cache.add.side_effect = [False, False, True]

        outcome = gateway._check_rate_limit("create-domain")

        self.assertEqual(outcome, RateLimitOutcome.ALLOWED)
        self.assertEqual(mock_cache.add.call_count, 3)
        mock_cache.get.assert_not_called()
        mock_cache.set.assert_not_called()
        mock_cache.incr.assert_not_called()

    @patch("apps.provisioning.virtualmin_gateway.cache")
    def test_rate_limit_rejects_when_all_atomic_slots_are_claimed(self, mock_cache: MagicMock) -> None:
        from apps.provisioning.virtualmin_gateway import VIRTUALMIN_RATE_LIMIT_MAX_CALLS  # noqa: PLC0415

        gateway = self._gateway()
        mock_cache.add.return_value = False

        self.assertEqual(gateway._check_rate_limit("create-domain"), RateLimitOutcome.EXHAUSTED)
        self.assertEqual(mock_cache.add.call_count, VIRTUALMIN_RATE_LIMIT_MAX_CALLS)
        mock_cache.incr.assert_not_called()

    @patch("apps.provisioning.virtualmin_gateway.cache")
    def test_rate_limit_fails_closed_when_counter_backend_fails(self, mock_cache: MagicMock) -> None:
        gateway = self._gateway()
        mock_cache.add.side_effect = RuntimeError("cache unavailable")

        # HIGH-2: a backend failure is distinct from genuine exhaustion so the
        # caller can avoid reporting it as a retriable rate-limit hit.
        self.assertEqual(gateway._check_rate_limit("create-domain"), RateLimitOutcome.BACKEND_ERROR)

    _LOCMEM: ClassVar[dict[str, Any]] = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "virtualmin-ratelimit-test",
        }
    }

    @override_settings(CACHES=_LOCMEM)
    def test_rate_limit_allows_exactly_max_then_denies_against_live_cache(self) -> None:
        """MEDIUM-5: prove the atomic slot claim against a REAL cache backend,
        not a mock — exactly MAX allowed, the next denied, and a fresh window
        resets."""
        from apps.provisioning.virtualmin_gateway import (  # noqa: PLC0415
            VIRTUALMIN_RATE_LIMIT_MAX_CALLS,
        )

        django_cache.clear()
        gateway = self._gateway()

        allowed = sum(
            1
            for _ in range(VIRTUALMIN_RATE_LIMIT_MAX_CALLS)
            if gateway._check_rate_limit("create-domain") is RateLimitOutcome.ALLOWED
        )
        self.assertEqual(allowed, VIRTUALMIN_RATE_LIMIT_MAX_CALLS)
        self.assertIs(gateway._check_rate_limit("create-domain"), RateLimitOutcome.EXHAUSTED)
        # A different operation has its own slot namespace.
        self.assertIs(gateway._check_rate_limit("other-op"), RateLimitOutcome.ALLOWED)

    @patch.object(VirtualminGateway, "_check_rate_limit", return_value=RateLimitOutcome.BACKEND_ERROR)
    @patch.object(VirtualminGateway, "_validate_server_health")
    def test_call_reports_cache_backend_failure_as_non_retriable(
        self, mock_health: MagicMock, _mock_rl: MagicMock
    ) -> None:
        """HIGH-2: a rate-limit BACKEND failure must not surface as a retriable
        'rate limit exceeded' — that invites retry loops against a dead cache."""
        from apps.common.types import Ok, Retriability, retriability_of  # noqa: PLC0415
        from apps.provisioning.virtualmin_gateway import VirtualminRateLimitedError  # noqa: PLC0415

        mock_health.return_value = Ok(True)
        gateway = self._gateway()

        result = gateway.call("list-domains", {})

        self.assertTrue(result.is_err())
        self.assertNotIsInstance(result.unwrap_err(), VirtualminRateLimitedError)
        self.assertNotEqual(retriability_of(result), Retriability.RETRIABLE)
