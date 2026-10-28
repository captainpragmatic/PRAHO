"""No-side-effect provider contracts and real process deadline enforcement."""

import json
import subprocess
import sys
import time
from unittest.mock import MagicMock, Mock, patch

import requests
from django.test import SimpleTestCase, override_settings

from apps.common import system_status_probes as probes


def response(data: object, status: int = 200) -> MagicMock:
    result = MagicMock(spec=requests.Response)
    result.status_code = status
    result.__enter__.return_value = result
    result.iter_content.return_value = [json.dumps(data).encode()]
    return result


class ProviderProbeTests(SimpleTestCase):
    @patch.object(probes, "safe_request")
    def test_documented_anaf_empty_window_is_success_but_errors_still_fail(self, request: Mock) -> None:
        empty = {"eroare": "Nu exista mesaje in intervalul selectat", "titlu": "Lista Mesaje"}
        request.return_value = response(empty)
        self.assertEqual(probes.run_probe("efactura", {"url": "https://api.anaf.ro/check"}), probes.ProbeCode.OK)
        for data in (
            {**empty, "error": "access denied"},
            {**empty, "eroare": "quota exhausted"},
            {**empty, "eroare": "invalid dates"},
            {**empty, "titlu": "unknown operation"},
        ):
            with self.subTest(data=data):
                request.return_value = response(data)
                self.assertEqual(
                    probes.run_probe("efactura", {"url": "https://api.anaf.ro/check"}),
                    probes.ProbeCode.INVALID_RESPONSE,
                )
        request.return_value = response(empty, 401)
        self.assertEqual(
            probes.run_probe("efactura", {"url": "https://api.anaf.ro/check"}), probes.ProbeCode.UNAUTHORIZED
        )

    @patch.object(probes, "safe_request")
    @patch("boto3.session.Session")
    def test_ses_uses_effective_region_and_credentials_without_sdk_request(self, session: Mock, request: Mock) -> None:
        request.return_value = response({"SendingEnabled": True, "ProductionAccessEnabled": True})
        config = {
            "session_params": {"profile_name": "mail"},
            "client_params": {
                "region_name": "eu-west-1",
                "aws_access_key_id": "test-access",
                "aws_secret_access_key": "test-secret",
                "aws_session_token": "test-token",
            },
        }
        self.assertEqual(probes.run_probe("ses", config), probes.ProbeCode.OK)
        session.assert_called_once_with(profile_name="mail")
        session.return_value.client.assert_not_called()
        session.return_value.get_credentials.assert_not_called()
        self.assertEqual(request.call_args.args, ("GET", "https://email.eu-west-1.amazonaws.com/v2/email/account"))
        self.assertIn("eu-west-1/ses/aws4_request", request.call_args.kwargs["headers"]["Authorization"])
        self.assertEqual(request.call_args.kwargs["headers"]["X-Amz-Security-Token"], "test-token")

    @patch.object(probes, "safe_request")
    def test_only_explicit_permission_codes_are_classified(self, request: Mock) -> None:
        request.return_value = response({"error": {"code": "permission_missing"}}, 403)
        self.assertEqual(
            probes.run_probe("stripe", {"url": "https://api.stripe.com/v1/account"}), probes.ProbeCode.PERMISSION
        )
        request.return_value = response({"error": {"code": "account_restricted"}}, 403)
        self.assertEqual(
            probes.run_probe("stripe", {"url": "https://api.stripe.com/v1/account"}), probes.ProbeCode.FORBIDDEN
        )

    @patch.object(probes, "safe_request")
    def test_provider_success_contracts_and_read_only_transport(self, request: Mock) -> None:
        for provider, host, data in (
            ("stripe", "api.stripe.com", {"object": "account", "id": "acct_1", "charges_enabled": True}),
            ("sendgrid", "api.sendgrid.com", {"scopes": ["mail.send"]}),
            ("mailgun", "api.eu.mailgun.net", {"domain": {"state": "active"}}),
            ("ses", "email.eu-west-1.amazonaws.com", {"SendingEnabled": True, "ProductionAccessEnabled": True}),
            ("efactura", "api.anaf.ro", {"mesaje": [], "numar_total_inregistrari": 0}),
        ):
            with self.subTest(provider=provider):
                request.return_value = response(data)
                self.assertEqual(
                    probes._http(provider, {"host": host, "url": f"https://{host}/check"}), probes.ProbeCode.OK
                )
                self.assertEqual(request.call_args.args[0], "GET")
                policy = request.call_args.kwargs["policy"]
                self.assertFalse(policy.allow_redirects)
                self.assertFalse(policy.retry_connection_errors)
                self.assertEqual(policy.max_retries, 0)
                self.assertTrue(request.call_args.kwargs["stream"])

    @patch.object(probes, "safe_request")
    def test_http_failures_are_not_success_or_invented_permissions(self, request: Mock) -> None:
        for code, expected in (
            (401, probes.ProbeCode.UNAUTHORIZED),
            (403, probes.ProbeCode.FORBIDDEN),
            (429, probes.ProbeCode.THROTTLED),
            (500, probes.ProbeCode.UNAVAILABLE),
            (302, probes.ProbeCode.UNAVAILABLE),
        ):
            with self.subTest(code=code):
                request.return_value = response({"error": "private credential details"}, code)
                self.assertEqual(probes.run_probe("efactura", {"url": "https://api.anaf.ro/check"}), expected)

    @patch.object(probes, "safe_request")
    def test_anaf_error_or_missing_messages_cannot_be_empty_success(self, request: Mock) -> None:
        for data in ({"eroare": "private"}, {"error": "private", "mesaje": []}, {"unrelated": []}, {"mesaje": {}}, []):
            with self.subTest(data=data):
                request.return_value = response(data)
                self.assertEqual(
                    probes.run_probe("efactura", {"url": "https://api.anaf.ro/check"}),
                    probes.ProbeCode.INVALID_RESPONSE,
                )

    @patch.object(probes, "safe_request")
    def test_disabled_and_restricted_accounts(self, request: Mock) -> None:
        for provider, host, data, expected in (
            ("sendgrid", "api.sendgrid.com", {"scopes": []}, probes.ProbeCode.PERMISSION),
            ("mailgun", "api.mailgun.net", {"domain": {"state": "unverified"}}, probes.ProbeCode.DISABLED),
            (
                "stripe",
                "api.stripe.com",
                {"object": "account", "id": "acct_1", "charges_enabled": False},
                probes.ProbeCode.DISABLED,
            ),
            ("ses", "email.eu-west-1.amazonaws.com", {"SendingEnabled": False}, probes.ProbeCode.DISABLED),
            (
                "ses",
                "email.eu-west-1.amazonaws.com",
                {"SendingEnabled": True, "ProductionAccessEnabled": False},
                probes.ProbeCode.SANDBOX,
            ),
        ):
            with self.subTest(provider=provider, data=data):
                request.return_value = response(data)
                self.assertEqual(probes._http(provider, {"host": host, "url": f"https://{host}/check"}), expected)

    def test_response_cap_stops_reading_before_consuming_large_body(self) -> None:
        result = response({})
        consumed = []

        def chunks():
            yield b"x" * probes.MAX_RESPONSE_BYTES
            yield b"x"
            consumed.append(True)
            yield b"more private data"

        result.iter_content.return_value = chunks()
        self.assertEqual(probes._read_response(result), probes.ProbeCode.TOO_LARGE)
        self.assertEqual(consumed, [])
        result.__exit__.assert_called_once()

    def test_exact_response_cap_allows_valid_json(self) -> None:
        result = response({})
        payload = b'{"ok":true}'
        result.iter_content.return_value = [payload + b" " * (probes.MAX_RESPONSE_BYTES - len(payload))]
        self.assertEqual(probes._read_response(result), {"ok": True})

    @patch.object(probes, "safe_request", side_effect=RuntimeError("secret-api-key private-response"))
    def test_exception_is_sanitized(self, _request: Mock) -> None:
        self.assertEqual(
            probes.run_probe("stripe", {"url": "https://api.stripe.com/v1/account"}), probes.ProbeCode.UNAVAILABLE
        )

    @patch.object(probes, "safe_request")
    def test_unknown_host_never_receives_credentials(self, request: Mock) -> None:
        result = probes.run_probe(
            "stripe", {"url": "https://other.example/v1/account", "headers": {"Authorization": "private"}}
        )
        self.assertEqual(result, probes.ProbeCode.UNVERIFIED)
        request.assert_not_called()

    @patch("django.core.mail.backends.smtp.EmailBackend")
    def test_smtp_opens_without_sending(self, backend: Mock) -> None:
        config = {
            "host": "smtp.example",
            "port": 465,
            "username": "user",
            "password": "private",
            "use_ssl": True,
            "use_tls": False,
        }
        backend.return_value.__enter__.return_value.connection = object()
        self.assertEqual(probes.run_probe("smtp", config), probes.ProbeCode.OK)
        backend.assert_called_once_with(**config, timeout=3, fail_silently=False)
        backend.return_value.send_messages.assert_not_called()
        backend.return_value.__exit__.assert_called_once()

    @override_settings(
        EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend",
        EMAIL_HOST="runtime.example",
        EMAIL_PORT=465,
        EMAIL_HOST_USER="runtime-user",
        EMAIL_HOST_PASSWORD="runtime-pass",
        EMAIL_USE_SSL=True,
        EMAIL_USE_TLS=False,
    )
    def test_smtp_configuration_matches_django_backend(self) -> None:
        provider, config = probes.email_probe_config()
        self.assertEqual(provider, "smtp")
        self.assertEqual(config["host"], "runtime.example")
        self.assertEqual(config["username"], "runtime-user")
        self.assertTrue(config["use_ssl"])


class ProbeBudgetTests(SimpleTestCase):
    @patch.object(probes.subprocess, "Popen")
    def test_unserializable_config_never_starts_a_child(self, popen: Mock) -> None:
        result = probes.ProbeBudget().run("ses", {"invalid": object()})
        self.assertEqual(result, probes.ProbeCode.UNAVAILABLE)
        popen.assert_not_called()

    def test_real_child_is_killed_and_reaped_at_deadline(self) -> None:
        original_popen = subprocess.Popen
        children = []

        def sleeping_child(*args: object, **kwargs: object):
            child = original_popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
            children.append(child)
            return child

        started = time.monotonic()
        with patch.object(probes.subprocess, "Popen", side_effect=sleeping_child):
            result = probes.ProbeBudget(deadline=started + 0.2).run("stripe", {})
        self.assertEqual(result, probes.ProbeCode.TIMEOUT)
        self.assertLess(time.monotonic() - started, 2)
        self.assertIsNotNone(children[0].returncode)
        self.assertNotEqual(children[0].returncode, 0)

    @patch.object(probes.subprocess, "Popen")
    def test_expired_shared_budget_does_not_start_another_child(self, process: Mock) -> None:
        self.assertEqual(probes.ProbeBudget(deadline=0).run("stripe", {}), probes.ProbeCode.TIMEOUT)
        process.assert_not_called()

    @patch.object(probes.subprocess, "Popen")
    def test_credentials_only_go_through_stdin(self, popen: Mock) -> None:
        child = popen.return_value.__enter__.return_value
        child.communicate.return_value = ("ok", "")
        child.returncode = 0
        self.assertEqual(probes.ProbeBudget().run("stripe", {"secret": "private-key"}), probes.ProbeCode.OK)
        self.assertNotIn("private-key", str(popen.call_args))
        self.assertIn("private-key", child.communicate.call_args.args[0])

    def test_real_worker_protocol_smoke(self) -> None:
        self.assertEqual(probes.ProbeBudget().run("unsupported", {}), probes.ProbeCode.UNVERIFIED)
