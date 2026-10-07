"""Coverage additions for Virtualmin HTTP guards and retry outcomes."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from typing import cast
from unittest.mock import patch

import requests
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.common.credential_vault import CredentialAccessLog, CredentialData, CredentialVault
from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError
from apps.common.types import Err, Retriability, retriability_of
from apps.provisioning.virtualmin_gateway import (
    MAX_RESPONSE_SIZE_BYTES,
    VirtualminAPIError,
    VirtualminAuthError,
    VirtualminAuthorizationError,
    VirtualminConfig,
    VirtualminGateway,
    VirtualminRateLimitedError,
    VirtualminTransientError,
    explicit_rejection,
    get_virtualmin_timeouts,
)
from apps.settings.services import SettingsService
from tests.provisioning.test_cov_virtualmin_gateway_listing import gateway, http_response


class OversizedResponse(requests.Response):
    def iter_content(self, chunk_size: int | None = 1, decode_unicode: bool = False) -> Iterator[bytes]:
        yield b"x" * (MAX_RESPONSE_SIZE_BYTES + 1)


class VirtualminGatewayTransportCoverageTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.gateway = gateway()
        blocked = patch(
            "apps.provisioning.virtualmin_gateway.safe_request", side_effect=AssertionError("Unexpected HTTP dispatch")
        )
        blocked.start()
        self.addCleanup(blocked.stop)
        sleeper = patch("apps.provisioning.virtualmin_gateway.time.sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)
        result = SettingsService.update_setting("virtualmin.max_retries", 2)
        self.assertTrue(result.is_ok(), result)

    def test_dispatch_carries_credentials_parameters_and_per_call_timeout(self) -> None:
        sent: list[dict[str, object]] = []

        def transport(method: str, url: str, *, policy: OutboundPolicy, **kwargs: object) -> requests.Response:
            sent.append({"method": method, "url": url, "policy": policy, **kwargs})
            return http_response({"status": "success", "message": "remote result"})

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.gateway.call(
                "list-domains",
                {"domain": "alpha.example.test"},
                correlation_id="coverage",
                timeout_seconds=17,
            )
        self.assertTrue(result.unwrap().success)
        self.assertEqual(result.unwrap().data["message"], "remote result")
        self.assertEqual(sent[0]["method"], "GET")
        self.assertEqual(sent[0]["url"], self.gateway.server.api_url)
        self.assertEqual(sent[0]["auth"], ("test_user", "test_pass"))
        self.assertEqual(sent[0]["params"], {"program": "list-domains", "domain": "alpha.example.test", "json": "1"})
        policy = cast("OutboundPolicy", sent[0]["policy"])
        self.assertEqual(policy.timeout_seconds, 17.0)
        self.assertTrue(policy.require_https)
        self.assertTrue(policy.verify_tls)
        self.assertEqual(self.gateway.config.timeout, 30)

    def test_xml_and_text_formats_keep_normalized_payloads(self) -> None:
        for response_format, raw, expected in (
            (
                "xml",
                "<response><status>ok</status></response>",
                {"xml_response": "<response><status>ok</status></response>"},
            ),
            ("text", "Operation completed", {"raw_response": "Operation completed"}),
        ):
            with (
                self.subTest(response_format=response_format),
                patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response(raw)),
            ):
                result = self.gateway.call("info", response_format=response_format)
            self.assertTrue(result.unwrap().success)
            self.assertEqual(result.unwrap().data, expected)

    def test_invalid_program_and_format_return_terminal_validation_errors(self) -> None:
        for program, response_format in (("not-a-program", "json"), ("info", "yaml")):
            with self.subTest(program=program, response_format=response_format):
                result = self.gateway.call(program, response_format=response_format)
            self.assertIsInstance(result, Err)
            self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
            self.assertIn("Validation error:", str(result.unwrap_err()))

    def test_inactive_server_refuses_operations_but_auto_failed_server_allows_health_probe(self) -> None:
        self.gateway.server.status = "failed"
        self.gateway.server.failed_by_health_check = True
        self.gateway.server.save(update_fields=["status", "failed_by_health_check"])
        result = self.gateway.call("delete-domain", {"domain": "alpha.example.test"})
        self.assertIsInstance(result, Err)
        self.assertIn("not active", str(result.unwrap_err()))
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response({"status": "success"})
        ):
            self.assertTrue(self.gateway.call("info").unwrap().success)
        self.gateway.server.failed_by_health_check = False
        result = self.gateway.call("info")
        self.assertIsInstance(result, Err)
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_missing_credentials_fail_closed(self) -> None:
        self.gateway.server.set_api_password("")
        self.gateway.server.save(update_fields=["encrypted_api_password"])
        self.gateway.server.refresh_from_db()
        result = self.gateway.call("info")
        self.assertIsInstance(result, Err)
        self.assertIsInstance(result.unwrap_err(), VirtualminAuthError)
        self.assertIn("No usable Virtualmin credential", str(result.unwrap_err()))
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_https_and_certificate_guards_return_terminal_errors(self) -> None:
        self.gateway.server.use_ssl = False
        result = self.gateway.call("info")
        self.assertIsInstance(result, Err)
        self.assertEqual(str(result.unwrap_err()), "Virtualmin API requires HTTPS")
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)

        self.gateway.server.use_ssl = True
        config = VirtualminConfig(
            server=self.gateway.server,
            verify_ssl=False,
            use_credential_vault=False,
        )
        other = VirtualminGateway(config)
        result = other.call("info")
        self.assertIsInstance(result, Err)
        self.assertIn("requires a pinned SHA-256", str(result.unwrap_err()))

    def test_http_statuses_preserve_error_taxonomy_and_retry_signal(self) -> None:
        for status, error_type, signal, detail in (
            (401, VirtualminAuthError, Retriability.NOT_RETRIABLE, "Authentication failed"),
            (403, VirtualminAuthorizationError, Retriability.NOT_RETRIABLE, "Access forbidden"),
            (404, VirtualminAPIError, Retriability.NOT_RETRIABLE, "Client error: HTTP 404"),
            (429, VirtualminRateLimitedError, Retriability.RETRIABLE, "Server rate limit exceeded"),
            (503, VirtualminTransientError, Retriability.UNKNOWN, "Server error: HTTP 503"),
        ):
            with (
                self.subTest(status=status),
                patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response({}, status)),
            ):
                result = self.gateway.call("info")
            self.assertIsInstance(result, Err)
            self.assertIsInstance(result.unwrap_err(), error_type)
            self.assertEqual(retriability_of(result), signal)
            self.assertIn(detail, str(result.unwrap_err()))
            if status in {404, 503}:
                self.assertEqual(result.unwrap_err().http_status, status)

    def test_transport_failures_preserve_replay_safety_for_mutations(self) -> None:
        for failure, signal, detail in (
            (requests.exceptions.ConnectTimeout("fixture"), Retriability.RETRIABLE, "Connection timeout"),
            (requests.exceptions.ReadTimeout("fixture"), Retriability.UNKNOWN, "Read timeout"),
            (requests.exceptions.ConnectionError("fixture"), Retriability.UNKNOWN, "Connection error"),
            (requests.exceptions.RequestException("fixture"), Retriability.UNKNOWN, "Request error"),
            (requests.exceptions.SSLError("fixture"), Retriability.NOT_RETRIABLE, "SSL error"),
            (OutboundSecurityError("fixture"), Retriability.NOT_RETRIABLE, "Outbound security policy"),
        ):
            with (
                self.subTest(failure=failure),
                patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=failure),
            ):
                result = self.gateway.call("delete-domain", {"domain": "alpha.example.test"})
            self.assertIsInstance(result, Err)
            self.assertEqual(retriability_of(result), signal)
            self.assertIn(detail, str(result.unwrap_err()))

    def test_read_recovers_after_ambiguous_timeout(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[
                requests.exceptions.ReadTimeout("fixture"),
                http_response({"status": "success", "uptime": 42}),
            ],
        ):
            result = self.gateway.get_server_info()
        self.assertEqual(result.unwrap(), {"status": "success", "uptime": 42})

    def test_mutation_is_not_replayed_after_ambiguous_timeout(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[requests.exceptions.ReadTimeout("fixture"), http_response({"status": "success"})],
        ):
            result = self.gateway.call("delete-domain", {"domain": "alpha.example.test"})
        self.assertIsInstance(result, Err)
        self.assertEqual(retriability_of(result), Retriability.UNKNOWN)
        self.assertIn("Read timeout", str(result.unwrap_err()))

    def test_explicit_rate_limit_rejection_allows_mutation_to_recover(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[http_response({}, 429), http_response({"status": "success", "message": "deleted"})],
        ):
            result = self.gateway.call("delete-domain", {"domain": "alpha.example.test"})
        self.assertTrue(result.unwrap().success)
        self.assertEqual(result.unwrap().data["message"], "deleted")

    def test_response_size_limits_refuse_declared_and_streamed_oversize(self) -> None:
        declared = http_response({})
        declared.headers["content-length"] = str(MAX_RESPONSE_SIZE_BYTES + 1)
        streamed = OversizedResponse()
        streamed.status_code = 200
        for response, detail in ((declared, "Response too large"), (streamed, "Response exceeds size limit")):
            with (
                self.subTest(detail=detail),
                patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=response),
            ):
                result = self.gateway.call("info")
            self.assertIsInstance(result, Err)
            self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
            self.assertIn(detail, str(result.unwrap_err()))

    def test_parse_failure_retains_remote_diagnostic(self) -> None:
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response("Error: rejected")):
            result = self.gateway.call("info")
        self.assertFalse(result.unwrap().success)
        self.assertEqual(result.unwrap().data["error"], "Error: rejected")
        self.assertEqual(result.unwrap().raw_response, "Error: rejected")

    @override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
    def test_zero_qps_limit_returns_retriable_error(self) -> None:
        updated = SettingsService.update_setting("virtualmin.rate_limit_qps", 0)
        self.assertTrue(updated.is_ok(), updated)
        result = self.gateway.call("info")
        self.assertIsInstance(result, Err)
        self.assertIsInstance(result.unwrap_err(), VirtualminRateLimitedError)
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)
        self.assertIn("requests per second limit exceeded", str(result.unwrap_err()))

    def test_explicit_rejection_requires_remote_failure_evidence(self) -> None:
        for raw, expected in (
            ('{"status": "failure", "message": "quota exceeded"}', "quota exceeded"),
            ('{"success": false}', "rejected"),
            ('{"status": "success"}', None),
            ("{truncated", None),
            ("<html>proxy failure</html>", None),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(explicit_rejection(raw), expected)

    def test_corrupt_server_ciphertext_returns_sanitized_auth_error(self) -> None:
        self.gateway.server.encrypted_api_password = b"invalid-ciphertext"
        self.gateway.server.save(update_fields=["encrypted_api_password"])
        self.gateway.server.refresh_from_db()
        result = self.gateway.call("info")
        self.assertIsInstance(result, Err)
        self.assertIsInstance(result.unwrap_err(), VirtualminAuthError)
        self.assertIn("Credential decryption failed", str(result.unwrap_err()))
        self.assertNotIn("invalid-ciphertext", str(result.unwrap_err()))

    def test_real_vault_credentials_win_and_record_successful_access(self) -> None:
        stored = CredentialVault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=self.gateway.server.hostname,
                username="vault-user",
                password="vault-password",
            )
        )
        self.assertTrue(stored.is_ok(), stored)
        credential = stored.unwrap()
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.gateway.server))
        sent: list[object] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(kwargs["auth"])
            return http_response({"status": "success", "source": "vault-authenticated"})

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.gateway.call("info")
        self.assertEqual(result.unwrap().data["source"], "vault-authenticated")
        self.assertEqual(sent, [("vault-user", "vault-password")])
        credential.refresh_from_db()
        self.assertEqual(credential.access_count, 1)
        self.assertIsNotNone(credential.last_accessed)
        access = CredentialAccessLog.objects.get(credential=credential, access_reason="Virtualmin info")
        self.assertTrue(access.success)
        self.assertEqual(access.error_message, "")

    def test_expired_vault_credential_cannot_fall_back_to_valid_server_field(self) -> None:
        stored = CredentialVault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=self.gateway.server.hostname,
                username="expired-user",
                password="expired-password",
            )
        )
        self.assertTrue(stored.is_ok(), stored)
        credential = stored.unwrap()
        credential.expires_at = timezone.now() - timedelta(days=1)
        credential.save(update_fields=["expires_at"])
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.gateway.server))
        result = self.gateway.call("info")
        self.assertIsInstance(result, Err)
        self.assertIsInstance(result.unwrap_err(), VirtualminAuthError)
        self.assertIn("Vault credential unavailable", str(result.unwrap_err()))
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
        access = CredentialAccessLog.objects.get(credential=credential, access_reason="Virtualmin info")
        self.assertFalse(access.success)
        self.assertEqual(access.error_message, "Credential expired")

    def test_absent_vault_entry_uses_legacy_server_credential(self) -> None:
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.gateway.server))
        sent: list[object] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            sent.append(kwargs["auth"])
            return http_response({"status": "success", "source": "legacy-authenticated"})

        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport):
            result = self.gateway.call("info")
        self.assertEqual(result.unwrap().data["source"], "legacy-authenticated")
        self.assertEqual(sent, [("test_user", "test_pass")])

    @override_settings(
        VIRTUALMIN_TIMEOUTS={
            "API_REQUEST_TIMEOUT": 0,
            "READ_TIMEOUT": -1,
            "WRITE_TIMEOUT": "invalid",
            "API_BACKUP_TIMEOUT": 3601,
        }
    )
    def test_invalid_timeout_overrides_fall_back_and_long_timeouts_remain_explicit(self) -> None:
        timeouts = get_virtualmin_timeouts()
        self.assertEqual(timeouts["API_REQUEST_TIMEOUT"], 30)
        self.assertEqual(timeouts["READ_TIMEOUT"], 30)
        self.assertEqual(timeouts["WRITE_TIMEOUT"], 30)
        self.assertEqual(timeouts["API_BACKUP_TIMEOUT"], 3601)

    def test_unexpected_health_transport_failure_returns_unknown_error(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=RuntimeError("unexpected transport failure"),
        ):
            result = self.gateway.test_connection()
        self.assertIsInstance(result, Err)
        self.assertEqual(result.unwrap_err(), "Connection test error: unexpected transport failure")
        self.assertEqual(retriability_of(result), Retriability.UNKNOWN)
