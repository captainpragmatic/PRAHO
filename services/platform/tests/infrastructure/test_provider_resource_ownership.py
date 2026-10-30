"""Provider writes record their intent first, report uncertain outcomes as such, and touch only owned resources.

- A server-create whose answer was lost may have been billed: it is UNKNOWN, never "not created".
- A provider refusal is NOT_RETRIABLE: provably nothing was created.
- A delete is confirmed by re-reading the server.
- An SSH key or firewall with our name but someone else's labels is never replaced or deleted.
- Discovery is by the deployment's labels, so a name collision never adopts another owner's server.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import requests
from django.test import SimpleTestCase, TestCase
from hcloud import APIException
from hcloud.firewalls.client import BoundFirewall
from hcloud.ssh_keys.client import BoundSSHKey

from apps.common.types import Err, Ok, Retriability, retriability_of
from apps.infrastructure.cloud_gateway import CloudProviderGateway, ServerCreateRequest
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.hcloud_service import HcloudService
from apps.infrastructure.models import NodeDeployment
from tests.infrastructure.test_deployment_operation_ownership import _gateway, _pipeline_service
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _ok_dns_gateway
from tests.infrastructure.test_hcloud_ipv6_address import hcloud_server

OURS = "11111111-1111-1111-1111-111111111111"
THEIRS = "22222222-2222-2222-2222-222222222222"


def service_with_client() -> tuple[HcloudService, mock.Mock]:
    with mock.patch("apps.infrastructure.hcloud_service.Client") as client_cls:
        client = mock.Mock()
        client_cls.return_value = client
        return HcloudService(token="fake-token"), client


def ssh_key(client: mock.Mock, public_key: str, labels: dict[str, str]) -> BoundSSHKey:
    return BoundSSHKey(
        client.ssh_keys,
        {"id": 7, "name": "praho-node", "public_key": public_key, "fingerprint": "fp", "labels": labels},
    )


def request(labels: dict[str, str] | None = None) -> ServerCreateRequest:
    return ServerCreateRequest(
        name="node",
        server_type="cx23",
        location="hel1",
        ssh_keys=["praho-node"],
        labels=labels if labels is not None else {"praho-deployment": OURS},
    )


class ServerCreateOutcomeTests(SimpleTestCase):
    def test_a_provider_refusal_is_not_retriable(self) -> None:
        service, client = service_with_client()
        client.servers.get_all.return_value = []
        client.servers.create.side_effect = APIException("invalid_input", "unsupported location for server type", None)

        result = service.create_server(request())

        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_a_lost_response_is_unknown(self) -> None:
        service, client = service_with_client()
        client.servers.get_all.return_value = []
        client.servers.create.side_effect = requests.Timeout("read timed out")

        result = service.create_server(request())

        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.UNKNOWN)

    def test_a_create_whose_action_never_finished_is_unknown(self) -> None:
        service, client = service_with_client()
        client.servers.get_all.return_value = []
        client.servers.create.return_value.action.wait_until_finished.side_effect = RuntimeError("action timeout")

        result = service.create_server(request())

        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.UNKNOWN)


class ConfirmedDeleteTests(SimpleTestCase):
    def test_a_server_still_present_after_delete_is_not_confirmed(self) -> None:
        service, client = service_with_client()
        client.servers.get_by_id.return_value = hcloud_server()

        result = service.delete_server("42")

        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.UNKNOWN)

    def test_a_server_gone_on_reread_is_confirmed(self) -> None:
        service, client = service_with_client()
        client.servers.get_by_id.side_effect = [hcloud_server(), APIException("not_found", "server not found", None)]

        self.assertTrue(service.delete_server("42").is_ok())


class OwnedSshKeyTests(SimpleTestCase):
    def test_a_same_name_key_of_another_deployment_is_never_replaced(self) -> None:
        service, client = service_with_client()
        client.ssh_keys.get_by_name.return_value = ssh_key(client, "ssh-ed25519 THEIRS", {"praho-deployment": THEIRS})

        result = service.upload_owned_ssh_key("praho-node", "ssh-ed25519 OURS", {"praho-deployment": OURS})

        self.assertTrue(result.is_err())
        client.ssh_keys.delete.assert_not_called()
        client.ssh_keys.create.assert_not_called()

    def test_an_unlabelled_key_with_our_content_is_adopted_and_labelled(self) -> None:
        service, client = service_with_client()
        client.ssh_keys.get_by_name.return_value = ssh_key(client, "ssh-ed25519 OURS", {})

        result = service.upload_owned_ssh_key("praho-node", "ssh-ed25519 OURS", {"praho-deployment": OURS})

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(client.ssh_keys.update.call_args.kwargs["labels"], {"praho-deployment": OURS})
        client.ssh_keys.delete.assert_not_called()

    def test_our_own_stale_key_is_replaced(self) -> None:
        service, client = service_with_client()
        client.ssh_keys.get_by_name.return_value = ssh_key(client, "ssh-ed25519 OLD", {"praho-deployment": OURS})
        client.ssh_keys.create.return_value = ssh_key(client, "ssh-ed25519 OURS", {"praho-deployment": OURS})

        result = service.upload_owned_ssh_key("praho-node", "ssh-ed25519 OURS", {"praho-deployment": OURS})

        self.assertTrue(result.is_ok(), result)
        client.ssh_keys.delete.assert_called_once()
        self.assertEqual(client.ssh_keys.create.call_args.kwargs["labels"], {"praho-deployment": OURS})

    def test_deleting_a_key_already_gone_by_id_succeeds(self) -> None:
        service, client = service_with_client()
        client.ssh_keys.get_by_id.side_effect = APIException("not_found", "ssh key not found", None)

        self.assertTrue(service.delete_ssh_key_by_id("7").is_ok())


class LabelDiscoveryTests(SimpleTestCase):
    def test_servers_are_found_by_the_deployment_label_only(self) -> None:
        service, client = service_with_client()
        server = hcloud_server()
        server.labels = {"praho-deployment": OURS}
        client.servers.get_all.return_value = [server]

        result = service.find_servers_by_label(f"praho-deployment={OURS}")

        client.servers.get_all.assert_called_once_with(label_selector=f"praho-deployment={OURS}")
        self.assertEqual([info.server_id for info in result.unwrap()], ["42"])

    def test_firewall_create_adopts_the_deployment_own_firewall(self) -> None:
        service, client = service_with_client()
        client.firewalls.get_all.return_value = [BoundFirewall(client.firewalls, {"id": 5, "name": "praho-fw-node"})]

        result = service.create_firewall("praho-fw-node", [], labels={"deployment-id": OURS})

        self.assertEqual(result.unwrap(), "5")
        client.firewalls.create.assert_not_called()
        client.firewalls.get_all.assert_called_once_with(label_selector=f"deployment-id={OURS}")

    def test_firewalls_and_keys_are_found_by_label(self) -> None:
        service, client = service_with_client()
        client.firewalls.get_all.return_value = [BoundFirewall(client.firewalls, {"id": 5})]
        client.ssh_keys.get_all.return_value = [ssh_key(client, "k", {"praho-deployment": OURS})]

        self.assertEqual(service.find_firewalls_by_label(f"deployment-id={OURS}").unwrap(), ["5"])
        self.assertEqual(service.find_ssh_keys_by_label(f"praho-deployment={OURS}").unwrap(), ["7"])


class DiscoveryFailsClosedTests(SimpleTestCase):
    def test_a_provider_without_discovery_never_reports_nothing_found(self) -> None:
        adapter = mock.Mock()  # An adapter that inherits the base defaults instead of overriding them.

        self.assertTrue(CloudProviderGateway.find_servers_by_label(adapter, "praho-deployment=x").is_err())
        self.assertTrue(CloudProviderGateway.find_firewalls_by_label(adapter, "deployment-id=x").is_err())
        self.assertTrue(CloudProviderGateway.find_ssh_keys_by_label(adapter, "praho-deployment=x").is_err())
        self.assertTrue(CloudProviderGateway.upload_owned_ssh_key(adapter, "n", "k", {}).is_err())
        self.assertTrue(CloudProviderGateway.delete_ssh_key_by_id(adapter, "1").is_err())


class DeployRecordsProviderOutcomesTests(TestCase):
    def _deploy(self, gateway: mock.Mock, progress: Any = None) -> NodeDeployment:
        deployment = _create_deployment("pending")
        service = _pipeline_service()
        with (
            mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=_ok_dns_gateway()),
            mock.patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
        ):
            service.deploy_node(deployment=deployment, credentials={"api_token": "tok"}, progress_callback=progress)
        deployment.refresh_from_db()
        return deployment

    def _owned_gateway(self) -> mock.Mock:
        gateway = _gateway()
        gateway.upload_owned_ssh_key.return_value = Ok("praho-key")
        return gateway

    def test_intent_and_provenance_are_recorded_before_the_first_provider_write(self) -> None:
        seen: dict[str, Any] = {}
        gateway = self._owned_gateway()

        def upload(*args: Any, **kwargs: Any) -> Ok[str]:
            row = NodeDeployment.objects.get()
            seen.update(state=row.server_create_state, fingerprint=row.provider_token_fingerprint)
            return Ok("praho-key")

        gateway.upload_owned_ssh_key.side_effect = upload

        self._deploy(gateway)

        self.assertEqual(seen, {"state": "intent", "fingerprint": provider_token_fingerprint("tok")})

    def test_the_key_is_uploaded_with_the_deployment_labels(self) -> None:
        gateway = self._owned_gateway()

        deployment = self._deploy(gateway)

        labels = gateway.upload_owned_ssh_key.call_args.args[2]
        self.assertEqual(labels["praho-deployment"], str(deployment.correlation_id))
        gateway.upload_ssh_key.assert_not_called()

    def test_an_unknown_create_outcome_is_retained(self) -> None:
        gateway = self._owned_gateway()
        gateway.create_server.return_value = Err("lost", retriability=Retriability.UNKNOWN)

        deployment = self._deploy(gateway)

        self.assertEqual(deployment.status, "failed")
        self.assertEqual(deployment.server_create_state, "unknown")

    def test_a_refused_create_is_recorded_as_never_created(self) -> None:
        gateway = self._owned_gateway()
        gateway.create_server.return_value = Err("refused", retriability=Retriability.NOT_RETRIABLE)

        deployment = self._deploy(gateway)

        self.assertEqual(deployment.status, "failed")
        self.assertEqual(deployment.server_create_state, "none")

    def test_the_server_id_is_persisted_before_the_next_stage(self) -> None:
        seen: dict[str, Any] = {}

        def progress(update: Any) -> None:
            if update.stage == "update_deployment":
                row = NodeDeployment.objects.get()
                seen.update(server=row.external_node_id, state=row.server_create_state)

        self._deploy(self._owned_gateway(), progress)

        self.assertEqual(seen, {"server": "srv-1", "state": "created"})

    def test_a_reused_existing_server_keeps_created(self) -> None:
        gateway = self._owned_gateway()
        gateway.get_server.return_value = Ok(
            mock.Mock(server_id="srv-0", ipv4_address="1.2.3.4", ipv6_address="")
        )
        deployment = _create_deployment("pending", external_node_id="srv-0")
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            server_create_state="created", provider_token_fingerprint=provider_token_fingerprint("tok")
        )
        service = _pipeline_service()
        service._ssh_manager.get_deployment_key.return_value = Ok(mock.Mock(public_key="ssh-rsa AAAA"))
        with (
            mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=_ok_dns_gateway()),
            mock.patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
        ):
            result = service.deploy_node(deployment=deployment, credentials={"api_token": "tok"})

        self.assertTrue(result.is_ok(), result)
        deployment.refresh_from_db()
        self.assertEqual(deployment.server_create_state, "created")
        gateway.get_server.assert_called_once_with("srv-0")
        gateway.create_server.assert_not_called()
