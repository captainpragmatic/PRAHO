"""Every teardown entry point runs the shared teardown, so each refuses an occupied node and proves each step.

Entry points: destroy (test_node_teardown), the failed-deployment sweep, the stale-destroying recovery
sweep, the cleanup_deployments command, and a failed deploy's own compensation.
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from typing import Any
from unittest import mock

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.deployment_lifecycle import claim_operation, provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.tasks import cleanup_failed_deployments_task, recover_stuck_deployments_task
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service
from tests.infrastructure.test_node_admission_guard import make_node
from tests.infrastructure.test_node_admission_guard import make_service as make_hosting_service
from tests.infrastructure.test_node_teardown import cloud_gateway, dns_gateway

TOKEN = "sweep-token"


def _age(deployment: NodeDeployment, status: str, hours: int = 48, **fields: Any) -> NodeDeployment:
    NodeDeployment.objects.filter(pk=deployment.pk).update(
        status=status, updated_at=timezone.now() - timedelta(hours=hours), **fields
    )
    deployment.refresh_from_db()
    return deployment


def _occupied_failed_row() -> tuple[NodeDeployment, Any]:
    server, deployment = make_node("occupied")
    VirtualminAccount.objects.create(
        domain="tenant.example.com",
        service=make_hosting_service("tenant.example.com"),
        server=server,
        virtualmin_username="tenant",
        status="active",
    )
    return _age(deployment, "failed"), server


def _billed_failed_row(**fields: Any) -> NodeDeployment:
    deployment = _create_deployment("failed", external_node_id="srv-9")
    return _age(
        deployment,
        "failed",
        server_create_state="created",
        provider_token_fingerprint=provider_token_fingerprint(TOKEN),
        **fields,
    )


def _patched(cloud: mock.Mock, token: Any = None) -> tuple[Any, ...]:
    return (
        mock.patch("apps.infrastructure.node_teardown.get_cloud_gateway", return_value=cloud),
        mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=dns_gateway()),
        mock.patch(
            "apps.infrastructure.provider_config.get_provider_token", return_value=token or Ok(TOKEN)
        ),
        mock.patch("apps.infrastructure.ssh_key_manager.get_ssh_key_manager", return_value=_make_service()._ssh_manager),
    )


class OccupiedNodeTests(TestCase):
    def test_the_failed_sweep_refuses_an_occupied_node(self) -> None:
        deployment, server = _occupied_failed_row()
        cloud = cloud_gateway()
        a, b, c, d = _patched(cloud)
        with a, b, c, d:
            result = cleanup_failed_deployments_task()

        self.assertEqual(result["cleaned_count"], 0)
        deployment.refresh_from_db()
        server.refresh_from_db()
        self.assertEqual((deployment.status, server.status), ("failed", "active"))
        cloud.delete_server.assert_not_called()

    def test_the_cleanup_command_refuses_an_occupied_node(self) -> None:
        deployment, server = _occupied_failed_row()
        cloud = cloud_gateway()
        a, b, c, d = _patched(cloud)
        with a, b, c, d:
            call_command("cleanup_deployments", stdout=StringIO(), stderr=StringIO())

        deployment.refresh_from_db()
        server.refresh_from_db()
        self.assertEqual((deployment.status, server.status), ("failed", "active"))
        cloud.delete_server.assert_not_called()


class CommandProvesEachStepTests(TestCase):
    def test_a_missing_token_never_marks_a_billed_row_destroyed(self) -> None:
        deployment = _billed_failed_row()
        a, b, c, d = _patched(cloud_gateway(), token=Err("no credential"))
        with a, b, c, d:
            call_command("cleanup_deployments", stdout=StringIO(), stderr=StringIO())

        deployment.refresh_from_db()
        self.assertEqual((deployment.status, deployment.external_node_id), ("destroying", "srv-9"))

    def test_a_proven_teardown_marks_the_row_destroyed(self) -> None:
        deployment = _billed_failed_row()
        cloud = cloud_gateway()
        a, b, c, d = _patched(cloud)
        with a, b, c, d:
            call_command("cleanup_deployments", stdout=StringIO(), stderr=StringIO())

        deployment.refresh_from_db()
        self.assertEqual((deployment.status, deployment.external_node_id), ("destroyed", ""))
        cloud.delete_server.assert_called_once_with("srv-9")


class SweepTests(TestCase):
    def test_the_failed_sweep_skips_rows_that_need_reconciliation(self) -> None:
        deployment = _billed_failed_row(needs_reconciliation=True, reconciliation_reason="legacy")
        cloud = cloud_gateway()
        a, b, c, d = _patched(cloud)
        with a, b, c, d:
            cleanup_failed_deployments_task()

        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")
        cloud.find_servers_by_label.assert_not_called()

    def test_a_stale_destroying_row_resumes_to_destroyed(self) -> None:
        deployment = _billed_failed_row()
        claim_operation(deployment.pk, from_states=("failed",), to_status="destroying", kind="destroy").unwrap()
        _age(deployment, "destroying", hours=4)
        cloud = cloud_gateway()
        a, b, c, d = _patched(cloud)
        with a, b, c, d:
            recover_stuck_deployments_task()

        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroyed")


class CompensationWithdrawsDnsFirstTests(TestCase):
    def test_an_unconfirmed_dns_withdrawal_keeps_the_server(self) -> None:
        deployment = _create_deployment("provisioning_node", external_node_id="srv-5")
        tag = f"praho:node-deploy:{deployment.correlation_id}"
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            dns_record_ids=[{"zone_id": "z1", "record_id": "rA", "type": "A", "name": "n", "owner_tag": tag}]
        )
        deployment.refresh_from_db()
        cloud = cloud_gateway()
        dns = dns_gateway()
        dns.confirm_no_owned_records.return_value = Ok(False)

        with (
            mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=dns),
            mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value="tok"),
        ):
            _make_service()._cleanup_resources(cloud, [("firewall", "fw-1"), ("server", "srv-5")], deployment)

        cloud.delete_server.assert_not_called()


class MarkFailedNeverForcesTests(TestCase):
    def test_a_destroyed_row_is_not_forced_back_to_failed(self) -> None:
        deployment = _create_deployment("destroyed")

        _make_service()._mark_failed(deployment, "late error from an old worker")

        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroyed")
