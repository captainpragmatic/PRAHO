"""Before a new server is created, Hetzner is asked whether the size can still be ordered in the region."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.hcloud_service import HcloudService
from apps.infrastructure.models import CloudProvider, NodeDeployment, PanelType
from apps.infrastructure.ssh_key_manager import SSHKeyPair
from tests.helpers.node_catalogue import make_region, make_size
from tests.helpers.recorded_hcloud import CPX11, CX23, RecordedHcloudTransport

CREDENTIALS = {"api_token": "fixture-token"}
_DNS_OK = Ok(("dns-token", "zone-id"))
_KEY = Ok(SSHKeyPair(public_key="ssh-ed25519 AAAA fixture", private_key="fixture", fingerprint="fixture"))


class OrderableCheckTests(TestCase):
    def setUp(self) -> None:
        provider = CloudProvider.objects.create(name="Hetzner", provider_type="hetzner", code="het")
        self.hel1 = make_region(provider, "hel1")
        # The synced catalogue still offers cpx11 in hel1: Hetzner withdrew it after the last sync.
        self.cpx11 = make_size(provider, "cpx11", self.hel1)
        self.cx23 = make_size(provider, "cx23", self.hel1)
        self.panel = PanelType.objects.create(name="Virtualmin", panel_type="virtualmin", ansible_playbook="v.yml")
        self.transport = RecordedHcloudTransport([CPX11, CX23])
        self.gateway_kwargs: list[dict[str, Any]] = []
        with patch("apps.infrastructure.deployment_service.get_ansible_service", return_value=MagicMock()):
            self.service = NodeDeploymentService()
        self.service._ssh_manager = MagicMock()
        # Stop each run at the first vault write, so a passed check is visible and nothing else runs.
        self.service._ssh_manager.generate_deployment_key.return_value = Err("vault write reached")
        self.service._ssh_manager.get_deployment_key.return_value = Err("vault read reached")
        self.service._ansible = MagicMock()
        self.service._resolve_dns_config = MagicMock(return_value=Err("dns not needed here"))
        for target, value in (
            ("apps.infrastructure.deployment_service.get_cloud_gateway", self.gateway),
            ("apps.infrastructure.deployment_service.SettingsService.get_setting", lambda *_a, **_k: True),
        ):
            patcher = patch(target, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("apps.infrastructure.tasks.queue_sync_providers", return_value="sync-task")
        self.queue_sync = patcher.start()
        self.addCleanup(patcher.stop)

    def gateway(self, provider_type: str, token: str, **kwargs: Any) -> HcloudService:
        self.gateway_kwargs.append(kwargs)
        gateway = HcloudService(token=token, **kwargs)
        patcher = patch.object(gateway.client._client, "request", self.transport)
        patcher.start()
        self.addCleanup(patcher.stop)
        return gateway

    def deployment(self, size: Any, *, status: str = "pending", external_node_id: str = "") -> NodeDeployment:
        deployment = NodeDeployment(
            environment="stg", node_type="sha", provider=size.provider, region=self.hel1, node_size=size,
            panel_type=self.panel, hostname="stg-sha-het-fi-hel1-002", dns_zone="nodes.example.com",
            node_number=2, status=status, external_node_id=external_node_id,
        )
        deployment.save()
        return deployment

    def urls(self) -> list[str]:
        return [url for url, _ in self.transport.requests]

    def test_withdrawn_size_fails_before_the_claim_and_any_write(self) -> None:
        deployment = self.deployment(self.cpx11)
        result = self.service.deploy_node(deployment, CREDENTIALS)
        self.assertTrue(result.is_err())
        self.assertIn("cpx11", result.unwrap_err())
        self.assertIn("hel1", result.unwrap_err())
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "pending")
        self.service._ssh_manager.generate_deployment_key.assert_not_called()
        self.assertEqual(self.transport.requests, [("/server_types", {"name": "cpx11"})])
        self.assertEqual(self.gateway_kwargs, [{"timeout": 10, "max_retries": 1}])
        self.queue_sync.assert_called_once_with()

    def test_provider_error_fails_without_a_verdict_or_sync(self) -> None:
        self.transport = MagicMock(side_effect=ConnectionError("read timed out"))
        deployment = self.deployment(self.cx23)
        result = self.service.deploy_node(deployment, CREDENTIALS)
        self.assertTrue(result.is_err())
        self.assertIn("read timed out", result.unwrap_err())
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "pending")
        self.service._ssh_manager.generate_deployment_key.assert_not_called()
        self.queue_sync.assert_not_called()

    def test_orderable_size_goes_on_to_the_pipeline(self) -> None:
        deployment = self.deployment(self.cx23)
        result = self.service.deploy_node(deployment, CREDENTIALS)
        self.assertEqual(result.unwrap_err(), "dns not needed here")
        self.assertEqual(self.urls(), ["/server_types"])
        self.queue_sync.assert_not_called()

    def test_existing_server_is_not_rechecked_before_it_is_looked_up(self) -> None:
        deployment = self.deployment(self.cpx11, external_node_id="4242")
        self.service._resolve_dns_config = MagicMock(return_value=Err("stop after the claim"))
        self.service.deploy_node(deployment, CREDENTIALS)
        self.assertNotIn("/server_types", self.urls())

    def test_stale_server_id_is_checked_before_creating_a_replacement(self) -> None:
        deployment = self.deployment(self.cpx11, external_node_id="4242")
        self.service._resolve_dns_config = MagicMock(return_value=_DNS_OK)
        self.service._ssh_manager.get_deployment_key.return_value = _KEY
        result = self.service.deploy_node(deployment, CREDENTIALS)
        self.assertTrue(result.is_err())
        self.assertIn("cpx11", result.unwrap_err())
        self.assertEqual(self.urls(), ["/servers/4242", "/server_types"])  # No key, firewall or server written.
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")
        self.assertEqual(deployment.external_node_id, "")
        self.queue_sync.assert_called_once_with()

    def test_retry_checks_once_before_counting_the_attempt(self) -> None:
        deployment = self.deployment(self.cx23, status="failed")
        self.service.retry_deployment(deployment, CREDENTIALS)
        deployment.refresh_from_db()
        self.assertEqual(deployment.retry_count, 1)
        self.assertEqual(self.urls(), ["/server_types"])

    def test_retry_of_withdrawn_size_is_refused_and_not_counted(self) -> None:
        deployment = self.deployment(self.cpx11, status="failed")
        result = self.service.retry_deployment(deployment, CREDENTIALS)
        self.assertTrue(result.is_err())
        self.assertIn("cpx11", result.unwrap_err())
        deployment.refresh_from_db()
        self.assertEqual((deployment.status, deployment.retry_count), ("failed", 0))
        self.service._ssh_manager.generate_deployment_key.assert_not_called()
