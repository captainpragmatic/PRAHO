"""Operation ownership: one worker owns a deployment's lifecycle writes, and a worker that lost it stops.

Two retries of the same failed row must run one pipeline and count one attempt. A worker resumed after
recovery reclaimed its row must write nothing and must not delete resources it no longer owns.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.common.types import Ok
from apps.infrastructure.cloud_gateway import ServerCreateResult
from apps.infrastructure.deployment_lifecycle import (
    OperationOwnershipLostError,
    claim_operation,
    invalidate_stale_operation,
    owned_transition,
    owned_update,
)
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.models import NodeDeployment, NodeSize
from apps.infrastructure.tasks import recover_stuck_deployments_task
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service, _ok_dns_gateway


def _pipeline_service() -> NodeDeploymentService:
    service = _make_service()
    service._ssh_manager.generate_deployment_key.return_value = Ok(MagicMock(public_key="ssh-rsa AAAA"))
    service._ansible.get_playbook_order.return_value = ["base.yml", "panel.yml", "harden.yml", "backup.yml"]
    service._ansible.run_playbook.return_value = Ok(MagicMock(success=True, stderr=""))
    service._validation.validate_node.return_value = Ok(MagicMock(all_passed=True, summary="ok"))
    service._registration.register_node.return_value = Ok(MagicMock(id=1))
    return service


def _gateway() -> MagicMock:
    gateway = MagicMock()
    gateway.upload_owned_ssh_key.return_value = Ok("praho-key")
    gateway.create_firewall.return_value = Ok("fw-1")
    gateway.create_server.return_value = Ok(ServerCreateResult(server_id="srv-1", ipv4_address="1.2.3.4"))
    gateway.delete_server.return_value = Ok(True)
    return gateway


class ClaimOperationTests(TestCase):
    def test_claim_rotates_a_token_distinct_from_the_correlation_id(self) -> None:
        deployment = _create_deployment("failed")

        lease = claim_operation(deployment.pk, from_states=("failed",), to_status="pending", kind="retry").unwrap()

        deployment.refresh_from_db()
        self.assertEqual(deployment.operation_token, lease.token)
        self.assertNotEqual(lease.token, deployment.correlation_id)
        self.assertEqual(deployment.operation_kind, "retry")
        self.assertEqual(deployment.status, "pending")

    def test_second_claim_from_the_same_state_is_refused(self) -> None:
        deployment = _create_deployment("failed")

        first = claim_operation(
            deployment.pk, from_states=("failed",), to_status="pending", kind="retry", increment_retry=True
        )
        second = claim_operation(
            deployment.pk, from_states=("failed",), to_status="pending", kind="retry", increment_retry=True
        )

        self.assertTrue(first.is_ok())
        self.assertTrue(second.is_err())
        deployment.refresh_from_db()
        self.assertEqual(deployment.retry_count, 1)

    def test_expected_token_must_match(self) -> None:
        deployment = _create_deployment("pending")
        claim_operation(deployment.pk, from_states=("pending",), to_status="pending", kind="deploy").unwrap()

        stale = claim_operation(
            deployment.pk,
            from_states=("pending",),
            to_status="provisioning_node",
            kind="deploy",
            expected_token=deployment.correlation_id,
        )

        self.assertTrue(stale.is_err())
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "pending")

    def test_stale_before_refuses_a_recently_written_row(self) -> None:
        deployment = _create_deployment("failed")

        result = claim_operation(
            deployment.pk,
            from_states=("failed",),
            to_status="destroying",
            kind="teardown",
            stale_before=timezone.now() - timedelta(hours=1),
        )

        self.assertTrue(result.is_err())


class OwnedWriteTests(TestCase):
    def test_a_rotated_token_refuses_phase_and_failure_writes(self) -> None:
        deployment = _create_deployment("pending")
        old = claim_operation(
            deployment.pk, from_states=("pending",), to_status="provisioning_node", kind="deploy"
        ).unwrap()
        deployment.refresh_from_db()
        invalidate_stale_operation(
            deployment.pk,
            from_states=("provisioning_node",),
            to_status="failed",
            stale_before=timezone.now() + timedelta(seconds=1),
            message="recovered",
        )

        with self.assertRaises(OperationOwnershipLostError):
            owned_update(old, deployment, external_node_id="srv-stale")
        with self.assertRaises(OperationOwnershipLostError):
            owned_transition(old, deployment, "configuring_dns")

        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")
        self.assertEqual(deployment.external_node_id, "")
        self.assertIsNone(deployment.operation_token)

    def test_release_clears_the_token(self) -> None:
        deployment = _create_deployment("failed")
        lease = claim_operation(deployment.pk, from_states=("failed",), to_status="pending", kind="retry").unwrap()
        deployment.refresh_from_db()

        owned_transition(lease, deployment, "failed", "stopped", release=True)

        deployment.refresh_from_db()
        self.assertIsNone(deployment.operation_token)
        self.assertEqual(deployment.operation_kind, "")


class TransitionToCompareAndSetTests(TestCase):
    def test_a_stale_instance_cannot_overwrite_a_newer_status(self) -> None:
        deployment = _create_deployment("completed")
        stale = NodeDeployment.objects.get(pk=deployment.pk)
        NodeDeployment.objects.filter(pk=deployment.pk).update(status="destroying")

        with self.assertRaises(ValidationError):
            stale.transition_to("stopped")

        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroying")


class RetryRunsOnePipelineTests(TestCase):
    def test_two_retries_loaded_before_either_claims_run_one_pipeline(self) -> None:
        deployment = _create_deployment("failed")
        first = NodeDeployment.objects.get(pk=deployment.pk)
        second = NodeDeployment.objects.get(pk=deployment.pk)
        service = _make_service()

        with patch.object(service, "deploy_node", return_value=Ok(MagicMock())) as pipeline:
            service.retry_deployment(first, credentials={"api_token": "t"})
            result = service.retry_deployment(second, credentials={"api_token": "t"})

        self.assertTrue(result.is_err())
        self.assertEqual(pipeline.call_count, 1)
        deployment.refresh_from_db()
        self.assertEqual(deployment.retry_count, 1)

    def test_retry_hands_its_token_to_the_pipeline(self) -> None:
        deployment = _create_deployment("failed")
        service = _make_service()

        with patch.object(service, "deploy_node", return_value=Ok(MagicMock())) as pipeline:
            service.retry_deployment(deployment, credentials={"api_token": "t"})

        deployment.refresh_from_db()
        self.assertEqual(pipeline.call_args.kwargs["expected_token"], deployment.operation_token)


class ResumedStaleWorkerTests(TestCase):
    def test_worker_resumed_after_recovery_writes_nothing_and_deletes_nothing(self) -> None:
        deployment = _create_deployment("pending")
        service = _pipeline_service()
        gateway = _gateway()

        def recovery_runs_during_the_panel_install(**_kwargs: object) -> Ok[MagicMock]:
            NodeDeployment.objects.filter(pk=deployment.pk).update(updated_at=timezone.now() - timedelta(hours=4))
            recover_stuck_deployments_task()
            return Ok(MagicMock(success=True, stderr=""))

        service._ansible.run_playbook.side_effect = recovery_runs_during_the_panel_install

        with (
            patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=_ok_dns_gateway()),
            patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
        ):
            result = service.deploy_node(deployment=deployment, credentials={"api_token": "t"})

        self.assertTrue(result.is_err())
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")
        self.assertIn("auto-recovered", deployment.status_message)
        gateway.delete_server.assert_not_called()
        self.assertEqual(service._ansible.run_playbook.call_count, 1)

    def test_recovery_rechecks_age_under_the_lock(self) -> None:
        deployment = _create_deployment("pending")
        lease = claim_operation(
            deployment.pk, from_states=("pending",), to_status="provisioning_node", kind="deploy"
        ).unwrap()

        recovered = invalidate_stale_operation(
            deployment.pk,
            from_states=("provisioning_node",),
            to_status="failed",
            stale_before=timezone.now() - timedelta(hours=3),
            message="stuck",
        )

        self.assertFalse(recovered)
        deployment.refresh_from_db()
        self.assertEqual(deployment.operation_token, lease.token)


class UpgradeDoesNotWriteStaleLifecycleTests(TestCase):
    @patch("apps.infrastructure.deployment_service.run_provider_command")
    def test_resize_saves_only_the_size(self, run_cmd: MagicMock) -> None:
        deployment = _create_deployment("completed", external_node_id="srv-1")
        run_cmd.return_value = Ok(MagicMock(success=True, stderr=""))
        new_size = NodeSize.objects.get(pk=deployment.node_size_id)
        new_size.pk = None
        new_size.provider_type_id = "cx22"
        new_size.save()
        NodeDeployment.objects.filter(pk=deployment.pk).update(status="destroying")

        result = _make_service().upgrade_node_size(deployment, new_size, credentials={"api_token": "t"})

        self.assertTrue(result.is_ok(), result)
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroying")
        self.assertEqual(deployment.node_size_id, new_size.pk)
