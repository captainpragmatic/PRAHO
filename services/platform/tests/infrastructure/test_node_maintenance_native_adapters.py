"""Actual node service entrypoints fence native calls and durably record command intent."""

from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TransactionTestCase, override_settings

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.infrastructure.deployment_lifecycle import claim_operation, reserve_operation
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.node_maintenance_execution import reconcile_direct_execution
from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution
from apps.infrastructure.provider_config import ProviderCommandResult
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(Q_CLUSTER={"name": "maintenance-native", "orm": "default", "retry": 100000})
class NodeMaintenanceNativeAdapterTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def deployment(self, *, bound: bool = True, status: str = "completed") -> NodeDeployment:
        deployment = _create_deployment(status, external_node_id="owned-native-fixture")
        if bound:
            deployment.virtualmin_server = self.node
            deployment.save(update_fields=["virtualmin_server"])
        return deployment

    def test_direct_reboot_refuses_a_window_without_calling_the_provider(self) -> None:
        deployment = self.deployment()
        self.start(self.window())
        with patch(
            "apps.infrastructure.deployment_service.run_provider_command",
            return_value=Ok(ProviderCommandResult(True, "", "", 0, "fixture")),
        ) as provider:
            result = _make_service().reboot_node(deployment, {}, user=self.actor)
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        provider.assert_not_called()

    def test_direct_security_maintenance_refuses_a_window_before_ansible(self) -> None:
        deployment = self.deployment()
        self.start(self.window())
        service = _make_service()
        service._ansible.run_playbook.return_value = Ok(
            AnsibleResult(success=True, playbook="virtualmin_harden.yml", stdout="", stderr="", return_code=0)
        )

        result = service.run_maintenance(deployment, user=self.actor)

        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        service._ansible.run_playbook.assert_not_called()

    def test_direct_power_on_refuses_a_running_window_before_the_provider(self) -> None:
        deployment = self.deployment(status="stopped")
        self.start(self.window())
        with patch(
            "apps.infrastructure.deployment_service.run_provider_command",
            return_value=Ok(ProviderCommandResult(True, "", "", 0, "fixture")),
        ) as provider:
            result = _make_service().start_node(deployment, {}, user=self.actor)
        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        provider.assert_not_called()

    def test_an_unbound_reboot_records_issued_ownership_outside_the_native_transaction(self) -> None:
        deployment = self.deployment(bound=False)
        observed: list[tuple[bool, bool]] = []

        def provider_boundary(**_kwargs: object) -> Ok[ProviderCommandResult]:
            observed.append(
                (
                    connection.in_atomic_block,
                    NodeMaintenanceExecution.objects.filter(deployment=deployment, phase="issued").exists(),
                )
            )
            return Ok(ProviderCommandResult(True, "", "", 0, "fixture"))

        with patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=provider_boundary):
            result = _make_service().reboot_node(deployment, {}, user=self.actor)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(observed, [(False, True)])
        execution = NodeMaintenanceExecution.objects.get(deployment=deployment)
        self.assertIsNone(execution.node_id)
        self.assertIsNone(execution.node_uuid)
        self.assertEqual(execution.deployment_correlation_id, deployment.correlation_id)
        self.assertEqual(execution.provider_resource_id, deployment.external_node_id)
        self.assertEqual(execution.phase, "awaiting_recovery", "Command ACK must not claim verified recovery")

    def test_provider_command_requires_an_exact_recorded_resource(self) -> None:
        deployment = self.deployment(bound=False)
        deployment.external_node_id = ""
        deployment.save(update_fields=["external_node_id"])
        with patch("apps.infrastructure.deployment_service.run_provider_command") as provider:
            result = _make_service().reboot_node(deployment, {}, user=self.actor)
        self.assertTrue(result.is_err())
        self.assertIn("No exact provider resource", result.unwrap_err())
        provider.assert_not_called()
        self.assertEqual(NodeMaintenanceExecution.objects.get(deployment=deployment).phase, "failed")

    def test_issued_unbound_native_work_refuses_both_pipeline_admissions(self) -> None:
        for admission in ("reserve", "claim"):
            with self.subTest(admission=admission):
                deployment = self.deployment(bound=False)
                observations: list[bool] = []

                def provider_boundary(
                    *,
                    current: NodeDeployment = deployment,
                    path: str = admission,
                    found: list[bool] = observations,
                    **_kwargs: object,
                ) -> Ok[ProviderCommandResult]:
                    self.assertFalse(connection.in_atomic_block)
                    self.assertTrue(
                        NodeMaintenanceExecution.objects.filter(deployment=current, phase="issued").exists()
                    )
                    if path == "reserve":
                        competing = reserve_operation(current.pk, from_states=("completed",), kind="destroy")
                    else:
                        competing = claim_operation(
                            current.pk, from_states=("completed",), to_status="destroying", kind="destroy"
                        )
                    found.append(competing.is_err())
                    return Ok(ProviderCommandResult(True, "", "", 0, "fixture"))

                with patch(
                    "apps.infrastructure.deployment_service.run_provider_command", side_effect=provider_boundary
                ):
                    result = _make_service().reboot_node(deployment, {}, user=self.actor)

                self.assertTrue(result.is_ok(), result)
                self.assertEqual(observations, [True], "A real issued owner must fence both public pipeline admissions")
                current = NodeDeployment.objects.get(pk=deployment.pk)
                self.assertIsNone(current.operation_token)
                self.assertIsNone(current.operation_reserved_at)
                self.assertEqual(current.status, "completed")

    def awaiting_recovery(self) -> tuple[NodeDeployment, NodeMaintenanceExecution]:
        deployment = self.deployment()
        with patch(
            "apps.infrastructure.deployment_service.run_provider_command",
            return_value=Ok(ProviderCommandResult(True, "", "", 0, "fixture")),
        ):
            result = _make_service().reboot_node(deployment, {}, user=self.actor)
        self.assertTrue(result.is_ok(), result)
        return deployment, NodeMaintenanceExecution.objects.get(deployment=deployment)

    def test_only_actual_operator_attestation_releases_acknowledged_direct_work(self) -> None:
        _deployment, execution = self.awaiting_recovery()
        with self.assertRaises(ValidationError):
            self.window()

        settled = reconcile_direct_execution(
            execution.pk,
            actor=self.actor,
            expected_phase="awaiting_recovery",
            outcome="verified",
            reason="The recorded target is checked and its recovery has been verified",
            commands_stopped=True,
            resource_confirmed=True,
        )

        self.assertEqual(settled.phase, "verified")
        self.assertEqual(self.window().status, "scheduled")

    def test_missing_attestation_cannot_release_an_uncertain_native_owner(self) -> None:
        _deployment, execution = self.awaiting_recovery()
        with self.assertRaises(ValidationError):
            reconcile_direct_execution(
                execution.pk,
                actor=self.actor,
                expected_phase="awaiting_recovery",
                outcome="verified",
                reason="Not yet confirmed",
                commands_stopped=False,
                resource_confirmed=True,
            )
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "awaiting_recovery")

    def test_a_stale_reconciliation_form_cannot_change_the_current_phase(self) -> None:
        _deployment, execution = self.awaiting_recovery()
        with self.assertRaises(ValidationError):
            reconcile_direct_execution(
                execution.pk,
                actor=self.actor,
                expected_phase="issued",
                outcome="verified",
                reason="Old form",
                commands_stopped=True,
                resource_confirmed=True,
            )
