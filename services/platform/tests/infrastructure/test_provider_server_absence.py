"""A deletion receipt or malformed provider response never proves confirmed absence."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from azure.core.exceptions import HttpResponseError
from django.test import SimpleTestCase

from apps.infrastructure.digitalocean_service import DigitalOceanService
from apps.infrastructure.vultr_service import VultrService


def sdk_reply(status, body):
    """The real pydo callback receives HTTP metadata separately from the decoded body."""

    def reply(**kwargs):
        callback = kwargs.get("cls")
        return (
            callback(SimpleNamespace(http_response=SimpleNamespace(status_code=status)), body, {}) if callback else body
        )

    return reply


def response(status, body=None):
    result = MagicMock(status_code=status)
    result.json.return_value = body
    result.raise_for_status.return_value = None
    return result


def http_error(status, message="provider response"):
    return requests.HTTPError(message, response=response(status))


class DigitalOceanAbsenceTests(SimpleTestCase):
    def setUp(self):
        self.service = object.__new__(DigitalOceanService)
        self.client = MagicMock()
        self.service.client = self.client

    def test_malformed_success_payloads_do_not_prove_absence(self):
        for body in (
            None,
            {},
            [],
            {"id": "not_found"},
            {"droplet": None},
            {"droplet": {}},
            {"droplet": []},
            {"droplet": {"id": 42}},
        ):
            self.client.droplets.get.side_effect = sdk_reply(200, body)
            with self.subTest(body=body):
                self.assertTrue(self.service.get_server("42").is_err())

    def test_exception_text_cannot_claim_not_found(self):
        structured = HttpResponseError(message="Forbidden: resource not found; request id 404")
        structured.status_code = 403
        for error in (
            RuntimeError("resource not found"),
            RuntimeError("connection failed with request id 404"),
            structured,
        ):
            with self.subTest(error=error):
                self.client.droplets.get.side_effect = error
                self.assertTrue(self.service.get_server("42").is_err())
                self.client.droplets.destroy.side_effect = error
                self.assertTrue(self.service.delete_server("42").is_err())

    def test_exact_http_404_is_idempotent_for_get_and_delete(self):
        self.client.droplets.get.side_effect = sdk_reply(404, {"id": "not_found", "message": "gone"})
        self.assertIsNone(self.service.get_server("42").unwrap())
        self.client.droplets.destroy.side_effect = sdk_reply(404, {"id": "not_found", "message": "gone"})
        self.assertIs(self.service.delete_server("42").unwrap(), True)
        self.assertIs(self.service.delete_server("42").unwrap(), True)

    @patch("apps.infrastructure.digitalocean_service._get_do_action_timeout", return_value=10)
    @patch("apps.infrastructure.digitalocean_service.time")
    def test_accepted_delete_must_wait_for_an_authoritative_absence(self, clock, _timeout):
        clock.monotonic.side_effect = [0, 0, 1]
        self.client.droplets.destroy.side_effect = sdk_reply(204, None)
        self.client.droplets.get.side_effect = [
            (200, {"droplet": {"id": 42, "name": "node", "status": "active"}}),
            (404, {"id": "not_found", "message": "gone"}),
        ]
        self.assertIs(self.service.delete_server("42").unwrap(), True)
        self.assertEqual(self.client.droplets.get.call_count, 2)
        clock.sleep.assert_called_once()

    @patch("apps.infrastructure.digitalocean_service._get_do_action_timeout", return_value=10)
    @patch("apps.infrastructure.digitalocean_service.time")
    def test_deletion_timeout_is_not_success(self, clock, _timeout):
        clock.monotonic.side_effect = [0, 0, 11]
        self.client.droplets.destroy.side_effect = sdk_reply(204, None)
        self.client.droplets.get.side_effect = sdk_reply(
            200, {"droplet": {"id": 42, "name": "node", "status": "active"}}
        )
        self.assertTrue(self.service.delete_server("42").is_err())

    @patch("apps.infrastructure.digitalocean_service._get_do_action_timeout", return_value=10)
    @patch("apps.infrastructure.digitalocean_service.time")
    def test_failed_authoritative_re_read_is_not_success(self, clock, _timeout):
        clock.monotonic.side_effect = [0, 0, 11]
        self.client.droplets.destroy.side_effect = sdk_reply(204, None)
        self.client.droplets.get.side_effect = RuntimeError("permission denied")
        self.assertTrue(self.service.delete_server("42").is_err())
        clock.sleep.assert_not_called()

    def test_real_pydo_preserves_status_instead_of_trusting_a_200_error_body(self):
        service = DigitalOceanService(token="offline-test-token")
        native = MagicMock(status_code=200, headers={}, content=b"{}")
        native.json.return_value = {"id": "not_found", "message": "malformed successful response"}
        with patch.object(service.client._client._pipeline, "run", return_value=SimpleNamespace(http_response=native)):
            self.assertTrue(service.get_server("42").is_err())
        service.client.close()

    def test_real_pydo_callback_handles_existing_and_absent_droplets(self):
        for status, body, absent in (
            (200, {"droplet": {"id": 42, "name": "node", "status": "active"}}, False),
            (404, {"id": "not_found", "message": "gone"}, True),
        ):
            service = DigitalOceanService(token="offline-test-token")
            native = MagicMock(status_code=status, headers={}, content=b"{}")
            native.json.return_value = body
            with (
                self.subTest(status=status),
                patch.object(
                    service.client._client._pipeline, "run", return_value=SimpleNamespace(http_response=native)
                ),
            ):
                result = service.get_server("42")
                self.assertTrue(result.is_ok())
                self.assertEqual(result.unwrap() is None, absent)
            service.client.close()

    @patch("apps.infrastructure.digitalocean_service._get_do_action_timeout", return_value=0)
    def test_zero_timeout_and_unexpected_delete_receipt_do_not_claim_success(self, _timeout):
        for status in (204, 200, 202):
            self.client.droplets.destroy.side_effect = sdk_reply(status, None)
            with self.subTest(status=status):
                self.assertTrue(self.service.delete_server("42").is_err())
        self.client.droplets.get.assert_not_called()


class VultrAbsenceTests(SimpleTestCase):
    def setUp(self):
        self.service = VultrService(token="offline-test-token")

    def test_malformed_success_payloads_do_not_prove_absence(self):
        for body in (
            None,
            {},
            [],
            {"instance": None},
            {"instance": {}},
            {"instance": []},
            {"instance": {"id": "node"}},
        ):
            with (
                self.subTest(body=body),
                patch("apps.infrastructure.vultr_service.safe_request", return_value=response(200, body)),
            ):
                self.assertTrue(self.service.get_server("node").is_err())

    @patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=10)
    @patch("apps.infrastructure.vultr_service.time")
    def test_accepted_delete_waits_for_authoritative_absence(self, clock, _timeout):
        clock.monotonic.side_effect = [0, 0, 1]
        with patch(
            "apps.infrastructure.vultr_service.safe_request",
            side_effect=[
                response(204),
                response(200, {"instance": {"id": "node", "status": "active"}}),
                http_error(404),
            ],
        ) as request:
            self.assertIs(self.service.delete_server("node").unwrap(), True)
        self.assertEqual([call.args[0] for call in request.call_args_list], ["DELETE", "GET", "GET"])
        clock.sleep.assert_called_once()

    @patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=10)
    @patch("apps.infrastructure.vultr_service.time")
    def test_deletion_timeout_is_not_success(self, clock, _timeout):
        clock.monotonic.side_effect = [0, 0, 11]
        with patch(
            "apps.infrastructure.vultr_service.safe_request",
            side_effect=[response(204), response(200, {"instance": {"id": "node", "status": "active"}})],
        ):
            self.assertTrue(self.service.delete_server("node").is_err())

    @patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=10)
    @patch("apps.infrastructure.vultr_service.time")
    def test_re_read_permission_or_transport_failure_is_not_success(self, clock, _timeout):
        for error in (
            http_error(403, "not found; request id 404"),
            requests.ConnectionError("connection failed"),
            requests.Timeout("timeout"),
        ):
            clock.monotonic.side_effect = [0, 0, 11]
            with (
                self.subTest(error=error),
                patch("apps.infrastructure.vultr_service.safe_request", side_effect=[response(204), error]),
            ):
                self.assertTrue(self.service.delete_server("node").is_err())
        clock.sleep.assert_not_called()

    def test_exact_not_found_remains_idempotent(self):
        with patch("apps.infrastructure.vultr_service.safe_request", side_effect=http_error(404)):
            self.assertIsNone(self.service.get_server("node").unwrap())
            self.assertIs(self.service.delete_server("node").unwrap(), True)
            self.assertIs(self.service.delete_server("node").unwrap(), True)

    @patch("apps.infrastructure.vultr_service._get_vultr_poll_timeout", return_value=0)
    def test_zero_timeout_and_unexpected_delete_receipt_do_not_claim_success(self, _timeout):
        for status in (204, 200, 202):
            with (
                self.subTest(status=status),
                patch("apps.infrastructure.vultr_service.safe_request", return_value=response(status)) as request,
            ):
                self.assertTrue(self.service.delete_server("node").is_err())
                self.assertEqual([call.args[0] for call in request.call_args_list], ["DELETE"])
