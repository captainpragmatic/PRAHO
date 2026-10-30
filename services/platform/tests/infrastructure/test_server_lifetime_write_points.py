"""Deploy, cleanup and teardown open, confirm, discard and close server lifetimes as the server comes and goes."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.common.types import Err, Ok, Retriability
from apps.infrastructure.cloud_gateway import ServerCreateResult
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeServerLifetime
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service
from tests.infrastructure.test_node_teardown import Harness


def _gateway(create: Any) -> MagicMock:
    gateway = MagicMock()
    gateway.upload_owned_ssh_key.return_value = Ok("praho-key")
    gateway.create_firewall.return_value = Ok("fw-1")
    gateway.create_server.return_value = create
    gateway.delete_server.return_value = Ok(True)
    gateway.delete_firewall.return_value = Ok(True)
    gateway.delete_ssh_key.return_value = Ok(True)
    return gateway


def _deploy(deployment: NodeDeployment, gateway: MagicMock, *, dns_fails: bool = True) -> Any:
    service = _make_service()
    service._ssh_manager.generate_deployment_key.return_value = Ok(MagicMock(public_key="ssh-rsa AAAA"))
    # Stop right after provisioning: the DNS step fails, which is not under test here.
    service._configure_dns = MagicMock(return_value=Err("dns stops the pipeline here"))
    service._resolve_dns_config = MagicMock(return_value=Ok(("dns-token", "zone")))
    with (
        patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
        patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
    ):
        return service.deploy_node(deployment=deployment, credentials={"api_token": "test-token"})


def _lifetimes(deployment: NodeDeployment) -> list[tuple[str, bool, bool]]:
    """(server id, open, legacy) per lifetime, oldest first."""
    return [
        (lt.server_id, lt.ended_at is None, lt.legacy)
        for lt in NodeServerLifetime.objects.filter(deployment=deployment).order_by("started_at", "created_at")
    ]


class DeployWritePointTests(TestCase):
    def test_a_created_server_gets_a_confirmed_lifetime(self) -> None:
        deployment = _create_deployment("pending")
        gateway = _gateway(Ok(ServerCreateResult(server_id="srv-1", ipv4_address="1.2.3.4")))
        gateway.delete_server.return_value = Err("kept for this test")  # Cleanup keeps the server.
        _deploy(deployment, gateway)
        self.assertEqual(_lifetimes(deployment), [("srv-1", True, False)])

    def test_a_refused_create_bills_nothing(self) -> None:
        deployment = _create_deployment("pending")
        _deploy(deployment, _gateway(Err("invalid server type", retriability=Retriability.NOT_RETRIABLE)))
        self.assertEqual(_lifetimes(deployment), [])

    def test_a_lost_create_outcome_stays_billed_until_teardown_proves_it_gone(self) -> None:
        deployment = _create_deployment("pending")
        _deploy(deployment, _gateway(Err("read timed out", retriability=Retriability.RETRIABLE)))
        self.assertEqual(_lifetimes(deployment), [("", True, False)])

    def test_a_replaced_stale_server_keeps_the_window_recorded_in_the_row(self) -> None:
        deployment = _create_deployment("pending", external_node_id="old-vm")
        started = timezone.now() - timedelta(hours=5)
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            started_at=started, server_create_state="created", provider_token_fingerprint=provider_token_fingerprint("test-token")
        )
        deployment.refresh_from_db()
        gateway = _gateway(Ok(ServerCreateResult(server_id="srv-2", ipv4_address="1.2.3.4")))
        gateway.get_server.return_value = Ok(None)  # The stored server is gone.
        gateway.delete_server.return_value = Err("kept for this test")
        _deploy(deployment, gateway)
        self.assertEqual(_lifetimes(deployment), [("", False, True), ("srv-2", True, False)])
        legacy = NodeServerLifetime.objects.get(deployment=deployment, legacy=True)
        self.assertEqual(legacy.started_at, started)

    def test_cleanup_that_deletes_the_new_server_closes_its_lifetime(self) -> None:
        deployment = _create_deployment("pending")
        _deploy(deployment, _gateway(Ok(ServerCreateResult(server_id="srv-1", ipv4_address=""))))
        self.assertEqual(_lifetimes(deployment), [("srv-1", False, False)])


class TeardownWritePointTests(TestCase):
    def test_teardown_closes_every_open_lifetime_including_an_unconfirmed_one(self) -> None:
        h = Harness()
        NodeServerLifetime.objects.create(
            deployment=h.deployment, server_id="srv-1", node_size=h.deployment.node_size, monthly_cost_eur=3,
            started_at=timezone.now() - timedelta(hours=2),
        )
        NodeServerLifetime.objects.create(
            deployment=h.deployment, server_id="", node_size=h.deployment.node_size, monthly_cost_eur=3,
            started_at=timezone.now() - timedelta(hours=1),
        )
        self.assertTrue(h.destroy().is_ok())
        self.assertEqual(h.row().status, "destroyed")
        self.assertFalse(NodeServerLifetime.objects.filter(deployment=h.deployment, ended_at__isnull=True).exists())
