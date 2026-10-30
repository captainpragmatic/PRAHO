"""Read-only lookups reconciliation uses to look for anything a deployment may still own.

Every lookup reports an error as an error: an adapter that cannot look something up never answers
"nothing found", because reconciliation treats an empty answer as evidence.
"""

from __future__ import annotations

import json
from typing import Any
from unittest import mock

import requests
from django.test import SimpleTestCase
from hcloud import APIException
from hcloud.firewalls.client import BoundFirewall
from hcloud.ssh_keys.client import BoundSSHKey

from apps.infrastructure.cloud_gateway import CloudProviderGateway
from apps.infrastructure.dns_gateway import CloudflareDnsGateway, DnsProviderGateway
from tests.infrastructure.test_hcloud_ipv6_address import hcloud_server, service_with_client


class HetznerNameLookupTests(SimpleTestCase):
    def test_a_server_is_found_by_its_name(self) -> None:
        service, client = service_with_client()
        client.servers.get_by_name.return_value = hcloud_server()

        self.assertEqual([s.server_id for s in service.find_servers_by_name("node").unwrap()], ["42"])
        client.servers.get_by_name.assert_called_once_with("node")

    def test_no_server_by_that_name_is_an_empty_answer(self) -> None:
        service, client = service_with_client()
        client.servers.get_by_name.return_value = None

        self.assertEqual(service.find_servers_by_name("node").unwrap(), [])

    def test_a_failed_lookup_is_an_error(self) -> None:
        service, client = service_with_client()
        client.servers.get_by_name.side_effect = requests.ConnectionError("down")

        self.assertTrue(service.find_servers_by_name("node").is_err())

    def test_firewalls_and_keys_are_found_by_name(self) -> None:
        service, client = service_with_client()
        client.firewalls.get_by_name.return_value = BoundFirewall(client.firewalls, {"id": 5})
        client.ssh_keys.get_by_name.return_value = BoundSSHKey(client.ssh_keys, {"id": 7})

        self.assertEqual(service.find_firewalls_by_name("praho-fw-node").unwrap(), ["5"])
        self.assertEqual(service.find_ssh_keys_by_name("praho-node").unwrap(), ["7"])

    def test_keys_are_found_by_fingerprint(self) -> None:
        service, client = service_with_client()
        client.ssh_keys.get_all.return_value = [BoundSSHKey(client.ssh_keys, {"id": 9})]

        self.assertEqual(service.find_ssh_keys_by_fingerprint("aa:bb").unwrap(), ["9"])
        client.ssh_keys.get_all.assert_called_once_with(fingerprint="aa:bb")

    def test_a_recorded_firewall_id_is_checked(self) -> None:
        service, client = service_with_client()
        client.firewalls.get_by_id.side_effect = APIException("not_found", "firewall not found", None)
        self.assertFalse(service.firewall_exists("5").unwrap())

        client.firewalls.get_by_id.side_effect = None
        client.firewalls.get_by_id.return_value = BoundFirewall(client.firewalls, {"id": 5})
        self.assertTrue(service.firewall_exists("5").unwrap())

        client.firewalls.get_by_id.side_effect = APIException("forbidden", "no", None)
        self.assertTrue(service.firewall_exists("5").is_err())


def _response(status: int, body: Any = None) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp._content = b"" if body is None else json.dumps(body).encode()
    return resp


class CloudflareLookupTests(SimpleTestCase):
    def _gateway(self, responses: list[requests.Response]) -> tuple[CloudflareDnsGateway, mock.MagicMock]:
        gateway = CloudflareDnsGateway(token="tok")
        patcher = mock.patch.object(gateway, "_request", side_effect=responses)
        request = patcher.start()
        self.addCleanup(patcher.stop)
        return gateway, request

    def test_records_by_name_keep_only_address_and_alias_records(self) -> None:
        listing = {
            "success": True,
            "result": [{"id": "a", "type": "A"}, {"id": "t", "type": "TXT"}, {"id": "c", "type": "CNAME"}],
            "result_info": {},
        }
        gateway, request = self._gateway([_response(200, listing)])

        found = gateway.find_records_by_name("z1", "node.example.com").unwrap()

        self.assertEqual([r["id"] for r in found], ["a", "c"])
        self.assertEqual(request.call_args.kwargs["params"]["name"], "node.example.com")

    def test_a_record_is_read_by_id_and_a_404_is_none(self) -> None:
        gateway, _request = self._gateway([_response(404)])

        self.assertIsNone(gateway.get_record("z1", "rA").unwrap())

    def test_a_transport_error_is_an_error(self) -> None:
        gateway, _request = self._gateway([])
        with mock.patch.object(gateway, "_request", side_effect=requests.ConnectionError("down")):
            self.assertTrue(gateway.get_record("z1", "rA").is_err())
            self.assertTrue(gateway.find_records_by_name("z1", "n").is_err())


class LookupsFailClosedTests(SimpleTestCase):
    def test_adapters_without_the_lookups_never_answer_nothing_found(self) -> None:
        adapter = mock.Mock()

        self.assertTrue(CloudProviderGateway.find_servers_by_name(adapter, "n").is_err())
        self.assertTrue(CloudProviderGateway.find_firewalls_by_name(adapter, "n").is_err())
        self.assertTrue(CloudProviderGateway.find_ssh_keys_by_name(adapter, "n").is_err())
        self.assertTrue(CloudProviderGateway.find_ssh_keys_by_fingerprint(adapter, "f").is_err())
        self.assertTrue(CloudProviderGateway.firewall_exists(adapter, "1").is_err())
        self.assertTrue(DnsProviderGateway.get_record(adapter, "z", "r").is_err())
        self.assertTrue(DnsProviderGateway.find_records_by_name(adapter, "z", "n").is_err())
