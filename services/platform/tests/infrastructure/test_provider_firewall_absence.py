"""Only native provider absence evidence can complete resource deletion."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from azure.core.exceptions import HttpResponseError
from django.test import SimpleTestCase
from hcloud import APIException
from hcloud.images.client import BoundImage

from apps.infrastructure.digitalocean_service import DigitalOceanService
from apps.infrastructure.hcloud_service import HcloudService


def sdk_reply(status, body=None):
    """Exercise pydo's real HTTP-metadata callback rather than inventing an SDK exception."""

    def reply(**kwargs):
        callback = kwargs.get("cls")
        return (
            callback(SimpleNamespace(http_response=SimpleNamespace(status_code=status)), body, {}) if callback else body
        )

    return reply


class HetznerExactAbsenceTests(SimpleTestCase):
    operations = (
        ("get_server", "servers"),
        ("delete_server", "servers"),
        ("delete_firewall", "firewalls"),
        ("firewall_exists", "firewalls"),
        ("delete_snapshot", "images"),
        ("delete_ssh_key_by_id", "ssh_keys"),
    )

    def test_exception_messages_never_prove_absence(self):
        for error in (
            RuntimeError("DNS transport endpoint not found (request 404)"),
            APIException("forbidden", "resource not found", None),
            APIException("timeout", "resource not found", None),
        ):
            for operation, endpoint in self.operations:
                with self.subTest(error=error, operation=operation):
                    service = object.__new__(HcloudService)
                    service.client = MagicMock()
                    getattr(service.client, endpoint).get_by_id.side_effect = error
                    self.assertTrue(getattr(service, operation)("42").is_err())
                    getattr(service.client, endpoint).delete.assert_not_called()

    def test_native_not_found_code_remains_authoritative_and_idempotent(self):
        for operation, endpoint in self.operations:
            with self.subTest(operation=operation):
                service = object.__new__(HcloudService)
                service.client = MagicMock()
                getattr(service.client, endpoint).get_by_id.side_effect = APIException("not_found", "absent", None)
                result = getattr(service, operation)("42")
                self.assertTrue(result.is_ok(), result)
                self.assertIs(result.unwrap(), None if operation == "get_server" else operation != "firewall_exists")
                getattr(service.client, endpoint).delete.assert_not_called()

    def test_accepted_server_delete_with_ambiguous_confirmation_remains_unconfirmed(self):
        service = object.__new__(HcloudService)
        service.client = MagicMock()
        server = MagicMock(id=42)
        service.client.servers.get_by_id.side_effect = [server, RuntimeError("transport endpoint not found")]
        result = service.delete_server("42")
        self.assertTrue(result.is_err())
        service.client.servers.delete.assert_called_once_with(server)
        self.assertEqual(service.client.servers.get_by_id.call_count, 2)

    def test_ambiguous_delete_exception_cannot_report_a_resource_as_gone(self):
        for operation, endpoint in self.operations:
            if not operation.startswith("delete_"):
                continue
            with self.subTest(operation=operation):
                service = object.__new__(HcloudService)
                service.client = MagicMock()
                if endpoint == "images":
                    service.client.images.get_by_id.return_value = BoundImage(service.client.images, {"id": 42})
                getattr(service.client, endpoint).delete.side_effect = RuntimeError("transport endpoint not found")
                self.assertTrue(getattr(service, operation)("42").is_err())
                getattr(service.client, endpoint).delete.assert_called_once()


class DigitalOceanFirewallAbsenceTests(SimpleTestCase):
    def setUp(self):
        self.service = object.__new__(DigitalOceanService)
        self.client = MagicMock()
        self.service.client = self.client
        timeout = patch("apps.infrastructure.digitalocean_service._get_do_action_timeout", return_value=10)
        timeout.start()
        self.addCleanup(timeout.stop)

    def test_exception_messages_and_permission_failures_never_confirm_absence(self):
        forbidden = HttpResponseError(message="Not found; request id 404")
        forbidden.status_code = 403
        for error in (RuntimeError("transport not found 404"), forbidden):
            with self.subTest(error=error):
                self.client.firewalls.delete.side_effect = error
                self.assertTrue(self.service.delete_firewall("fw-42").is_err())
        self.client.firewalls.get.assert_not_called()

    def test_exact_http_404_on_delete_remains_idempotent(self):
        self.client.firewalls.delete.side_effect = sdk_reply(404, {"id": "not_found"})
        self.assertIs(self.service.delete_firewall("fw-42").unwrap(), True)
        self.client.firewalls.get.assert_not_called()

    def test_native_raised_404_on_delete_remains_idempotent(self):
        error = HttpResponseError(message="Firewall absent")
        error.status_code = 404
        self.client.firewalls.delete.side_effect = error
        self.assertIs(self.service.delete_firewall("fw-42").unwrap(), True)

    @patch("apps.infrastructure.digitalocean_service.time")
    def test_delete_waits_until_a_native_reread_confirms_absence(self, clock):
        clock.monotonic.side_effect = [0, 0, 1]
        self.client.firewalls.delete.side_effect = sdk_reply(204)
        self.client.firewalls.get.side_effect = [(200, {"firewall": {"id": "fw-42"}}), (404, {"id": "not_found"})]
        self.assertIs(self.service.delete_firewall("fw-42").unwrap(), True)
        self.assertEqual([call[0] for call in self.client.firewalls.method_calls], ["delete", "get", "get"])
        clock.sleep.assert_called_once_with(5)

    @patch("apps.infrastructure.digitalocean_service.time")
    def test_still_present_at_deadline_is_an_error(self, clock):
        clock.monotonic.side_effect = [0, 0, 11]
        self.client.firewalls.delete.side_effect = sdk_reply(204)
        self.client.firewalls.get.side_effect = sdk_reply(200, {"firewall": {"id": "fw-42"}})
        result = self.service.delete_firewall("fw-42")
        self.assertTrue(result.is_err())
        self.assertIn("not confirmed", result.unwrap_err())

    def test_empty_malformed_and_wrong_resource_rereads_are_errors(self):
        self.client.firewalls.delete.side_effect = sdk_reply(204)
        for body in (
            None,
            {},
            [],
            {"id": "not_found"},
            {"firewall": None},
            {"firewall": {}},
            {"firewall": {"id": "fw-other"}},
        ):
            with self.subTest(body=body):
                self.client.firewalls.get.side_effect = sdk_reply(200, body)
                self.assertTrue(self.service.delete_firewall("fw-42").is_err())

    def test_post_delete_transport_and_permission_errors_are_not_absence(self):
        self.client.firewalls.delete.side_effect = sdk_reply(204)
        forbidden = HttpResponseError(message="resource not found 404")
        forbidden.status_code = 403
        for error in (RuntimeError("resource not found"), forbidden):
            with self.subTest(error=error):
                self.client.firewalls.get.side_effect = error
                self.assertTrue(self.service.delete_firewall("fw-42").is_err())

    def test_malformed_delete_response_and_unexpected_status_are_errors(self):
        for reply in (None, (200, {}), (202, None), (500, {"id": "not_found"})):
            with self.subTest(reply=reply):
                self.client.firewalls.delete.side_effect = None
                self.client.firewalls.delete.return_value = reply
                self.assertTrue(self.service.delete_firewall("fw-42").is_err())


class HetznerSnapshotAbsenceTests(SimpleTestCase):
    def setUp(self):
        self.service = object.__new__(HcloudService)
        self.client = MagicMock()
        self.service.client = self.client
        self.image = BoundImage(self.client.images, {"id": 42, "type": "snapshot"})
        self.client.images.delete.return_value = True

    def test_delete_receipt_is_not_confirmation_while_exact_image_is_still_visible(self):
        self.client.images.get_by_id.return_value = self.image
        result = self.service.delete_snapshot("42")
        self.assertTrue(result.is_err())
        self.assertIn("unconfirmed", result.unwrap_err())
        self.client.images.delete.assert_called_once_with(self.image)
        self.assertEqual([call.args for call in self.client.images.get_by_id.call_args_list], [(42,), (42,)])

    def test_exact_native_not_found_on_reread_confirms_deletion(self):
        self.client.images.get_by_id.side_effect = [self.image, APIException("not_found", "absent", None)]
        self.assertIs(self.service.delete_snapshot("42").unwrap(), True)
        self.assertEqual([call[0] for call in self.client.images.method_calls], ["get_by_id", "delete", "get_by_id"])
        self.assertEqual([call.args for call in self.client.images.get_by_id.call_args_list], [(42,), (42,)])

    def test_native_not_found_before_delete_is_idempotent_without_a_delete_call(self):
        self.client.images.get_by_id.side_effect = APIException("not_found", "absent", None)
        self.assertIs(self.service.delete_snapshot("42").unwrap(), True)
        self.client.images.delete.assert_not_called()

    def test_malformed_or_wrong_initial_image_cannot_be_deleted_or_claimed_absent(self):
        for image in (
            None,
            {},
            False,
            object(),
            BoundImage(self.client.images, {"id": None}),
            BoundImage(self.client.images, {"id": 43}),
            BoundImage(self.client.images, {"id": True}),
        ):
            with self.subTest(image=image):
                self.client.images.get_by_id.return_value = image
                self.assertTrue(self.service.delete_snapshot("42").is_err())
                self.client.images.delete.assert_not_called()

    def test_empty_malformed_or_wrong_confirmation_reply_is_not_absence(self):
        for reply in (None, {}, False, object(), BoundImage(self.client.images, {"id": 43})):
            with self.subTest(reply=reply):
                self.client.images.reset_mock()
                self.client.images.get_by_id.side_effect = [self.image, reply]
                self.assertTrue(self.service.delete_snapshot("42").is_err())
                self.client.images.delete.assert_called_once_with(self.image)

    def test_confirmation_permission_transport_and_timeout_errors_remain_errors(self):
        for error in (
            APIException("forbidden", "resource not found", None),
            RuntimeError("transport resource not found"),
            TimeoutError("snapshot confirmation timed out"),
        ):
            with self.subTest(error=error):
                self.client.images.get_by_id.side_effect = [self.image, error]
                self.assertTrue(self.service.delete_snapshot("42").is_err())
