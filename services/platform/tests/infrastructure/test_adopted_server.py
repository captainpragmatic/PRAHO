"""A server adopted by its deployment label keeps its key and survives a later failure of the retry.

After a lost create answer the server exists under the deployment's label, and the retry's create adopts it.
That server trusts only the first vault key, and its disks are the deployment's work so far: the retry must
reuse the stored key, and a later stage failing must fail the row with the server id kept, never delete it.
"""

from __future__ import annotations

from unittest import mock

from django.test import TestCase
from hcloud.servers.domain import IPv4Address

from apps.common.types import Ok
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.dns_gateway import ReconcileOutcome
from apps.infrastructure.hcloud_service import HcloudService
from apps.infrastructure.models import NodeDeployment
from tests.infrastructure.test_deployment_operation_ownership import _gateway, _pipeline_service
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _ok_dns_gateway
from tests.infrastructure.test_hcloud_ipv6_address import hcloud_server, service_with_client


class HetznerAdoptionTests(TestCase):
    def test_create_reports_an_adopted_server(self) -> None:
        service, client = service_with_client()
        existing = hcloud_server()
        existing.public_net.ipv4 = IPv4Address(ip="198.51.100.4", blocked=False, dns_ptr="")
        client.servers.get_all.return_value = [existing]
        from apps.infrastructure.cloud_gateway import ServerCreateRequest  # noqa: PLC0415

        result = HcloudService.create_server(
            service,
            ServerCreateRequest(
                name="n", server_type="cx23", location="hel1", ssh_keys=[], labels={"praho-deployment": "c"}
            ),
        )

        self.assertTrue(result.unwrap().adopted)
        client.servers.create.assert_not_called()


class AdoptedServerRetryTests(TestCase):
    def test_a_retry_that_adopts_reuses_the_key_and_keeps_the_server_on_failure(self) -> None:
        deployment = _create_deployment("pending")
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            ssh_key_credential_id="vault-key-1",
            server_create_state="unknown",
            provider_token_fingerprint=provider_token_fingerprint("tok"),
        )
        deployment.refresh_from_db()
        service = _pipeline_service()
        service._ssh_manager.get_deployment_key.return_value = Ok(mock.Mock(public_key="ssh-ed25519 FIRST"))
        gateway = _gateway()
        gateway.upload_owned_ssh_key.return_value = Ok("praho-key")
        from apps.infrastructure.cloud_gateway import ServerCreateResult  # noqa: PLC0415

        gateway.create_server.return_value = Ok(
            ServerCreateResult(server_id="srv-adopted", ipv4_address="1.2.3.4", adopted=True)
        )
        dns = _ok_dns_gateway()
        dns.reconcile_records.return_value = ReconcileOutcome(applied=[], error="cloudflare rejected the record")

        with (
            mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=dns),
            mock.patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
        ):
            result = service.deploy_node(deployment=deployment, credentials={"api_token": "tok"}, check_orderable=False)

        self.assertTrue(result.is_err())
        service._ssh_manager.generate_deployment_key.assert_not_called()
        gateway.delete_server.assert_not_called()
        deployment.refresh_from_db()
        self.assertEqual((deployment.status, deployment.external_node_id), ("failed", "srv-adopted"))


class AdoptedFirewallTests(TestCase):
    def test_the_firewall_of_an_adopted_server_is_not_deleted_on_a_later_failure(self) -> None:
        deployment = _create_deployment("pending")
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            server_create_state="unknown", provider_token_fingerprint=provider_token_fingerprint("tok")
        )
        deployment.refresh_from_db()
        service = _pipeline_service()
        gateway = _gateway()
        gateway.upload_owned_ssh_key.return_value = Ok("praho-key")
        from apps.infrastructure.cloud_gateway import ServerCreateResult  # noqa: PLC0415

        gateway.create_server.return_value = Ok(
            ServerCreateResult(server_id="srv-adopted", ipv4_address="1.2.3.4", adopted=True)
        )
        dns = _ok_dns_gateway()
        dns.reconcile_records.return_value = ReconcileOutcome(applied=[], error="cloudflare rejected the record")

        with (
            mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=dns),
            mock.patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
        ):
            service.deploy_node(deployment=deployment, credentials={"api_token": "tok"}, check_orderable=False)

        gateway.delete_firewall.assert_not_called()
