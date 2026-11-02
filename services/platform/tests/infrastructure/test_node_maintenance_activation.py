"""A late healthy start response cannot reopen a node owned by a newer stop."""

from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import paramiko
from django.db import close_old_connections, connection, connections, transaction
from django.test import TransactionTestCase, override_settings

from apps.common.types import Ok
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.node_maintenance_execution import reconcile_direct_execution
from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution
from apps.infrastructure.provider_config import ProviderCommandResult
from apps.provisioning.virtualmin_security import connection_identity
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture
from tests.provisioning.test_node_security_policy import ADMIN_NETWORKS, OPERATOR_KEY, node_policy_evidence

SQLParams = Sequence[object] | Mapping[str, object] | None
Execute = Callable[[str, SQLParams, bool, Mapping[str, object]], object]


@override_settings(Q_CLUSTER={"name": "maintenance-activation", "orm": "default", "retry": 100000})
class NodeMaintenanceActivationTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.node.status = "disabled"
        self.node.is_draining = True
        self.node.api_username = "praho-api"
        self.node.save(update_fields=["status", "is_draining", "api_username"])
        self.deployment = _create_deployment("stopped", external_node_id="owned-activation-fixture")
        host_key = paramiko.ECDSAKey.generate()
        self.deployment.ssh_host_keys = f"{host_key.get_name()} {host_key.get_base64()}"
        self.deployment.virtualmin_server = self.node
        self.deployment.save(update_fields=["virtualmin_server", "ssh_host_keys"])
        evidence = node_policy_evidence()
        # Substitute native observations, retaining real policy qualification and
        # its fresh identity binding under the activation transaction.
        self.enterContext(
            patch("apps.provisioning.virtualmin_security_tasks.collect_inspection", return_value=evidence)
        )
        self.enterContext(
            patch("apps.infrastructure.ansible_service.node_admin_allowed_cidrs", return_value=ADMIN_NETWORKS)
        )
        self.enterContext(
            patch(
                "apps.infrastructure.ansible_service.AnsibleService.operator_public_keys", return_value=(OPERATOR_KEY,)
            )
        )
        evidence["identity"] = connection_identity(self.node)

    def test_a_current_start_still_activates_a_healthy_node_and_clears_its_idle_drain_flag(self) -> None:
        with (
            patch("apps.infrastructure.deployment_service.run_provider_command") as provider,
            patch("apps.common.credential_vault.get_credential_vault") as vault,
            patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.test_connection") as health,
        ):
            provider.return_value = Ok(ProviderCommandResult(True, "", "", 0, "fixture"))
            vault.return_value.get_credential.return_value = Ok(("praho-api", "fixture-only", {}))
            health.return_value = Ok({"healthy": True})

            result = NodeDeploymentService().start_node(self.deployment, {}, user=self.actor)

        self.assertTrue(result.is_ok(), result)
        self.node.refresh_from_db()
        self.assertEqual((self.node.status, self.node.is_draining), ("active", False))
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, "completed")
        provider.assert_called_once()
        health.assert_called_once()

    def test_a_late_start_health_reply_cannot_reactivate_a_node_after_a_real_new_stop(self) -> None:
        operations: list[str] = []
        stop_observed: list[tuple[str, str, bool]] = []

        def provider_boundary(**kwargs: object) -> Ok[ProviderCommandResult]:
            self.assertFalse(connection.in_atomic_block)
            operation = str(kwargs["operation"])
            operations.append(operation)
            action = "start" if operation == "power_on" else "stop"
            self.assertTrue(
                NodeMaintenanceExecution.objects.filter(
                    deployment=self.deployment, action=action, phase="issued"
                ).exists()
            )
            self.assertEqual(kwargs["server_id"], self.deployment.external_node_id)
            return Ok(ProviderCommandResult(True, "", "", 0, "fixture"))

        def new_stop() -> None:
            # A separate public worker has its own connection and invocation context.
            close_old_connections()
            try:
                stopped = NodeDeploymentService().stop_node(
                    NodeDeployment.objects.get(pk=self.deployment.pk), {}, user=self.actor, force=True
                )
                self.assertTrue(stopped.is_ok(), stopped)
                self.node.refresh_from_db()
                stop_observed.append(
                    (
                        NodeDeployment.objects.get(pk=self.deployment.pk).status,
                        self.node.status,
                        self.node.is_draining,
                    )
                )
            finally:
                connections.close_all()

        def late_health_boundary() -> Ok[dict[str, bool]]:
            self.assertFalse(connection.in_atomic_block)
            old_start = NodeMaintenanceExecution.objects.get(deployment=self.deployment, action="start", phase="issued")
            reconcile_direct_execution(
                old_start.pk,
                actor=self.actor,
                expected_phase="issued",
                outcome="verified",
                reason="Provider command finished; operator closes this exact start before stopping the node",
                commands_stopped=True,
                resource_confirmed=True,
            )
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(new_stop).result(timeout=15)
            self.assertEqual(stop_observed, [("stopped", "disabled", True)])
            return Ok({"healthy": True})

        with (
            patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=provider_boundary),
            patch("apps.common.credential_vault.get_credential_vault") as vault,
            patch(
                "apps.provisioning.virtualmin_gateway.VirtualminGateway.test_connection",
                side_effect=late_health_boundary,
            ),
        ):
            vault.return_value.get_credential.return_value = Ok(("praho-api", "fixture-only", {}))

            result = NodeDeploymentService().start_node(self.deployment, {}, user=self.actor)

        self.assertEqual(operations, ["power_on", "power_off"])
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, "stopped")
        self.node.refresh_from_db()
        self.assertEqual((self.node.status, self.node.is_draining), ("disabled", True))
        self.assertTrue(result.is_err(), "The stale start must report loss of its activation authority")
        self.assertEqual(NodeMaintenanceExecution.objects.get(action="start").phase, "verified")
        self.assertEqual(NodeMaintenanceExecution.objects.get(action="stop").phase, "awaiting_recovery")

    def test_a_start_cannot_clear_drain_after_valid_activation_but_a_new_reboot_owns_the_node(self) -> None:
        observed: list[tuple[str, bool, str]] = []
        activation_updates: list[bool] = []

        def replace_with_reboot() -> None:
            self.assertFalse(connection.in_atomic_block)
            start = NodeMaintenanceExecution.objects.get(deployment=self.deployment, action="start", phase="issued")
            reconcile_direct_execution(
                start.pk,
                actor=self.actor,
                expected_phase="issued",
                outcome="verified",
                reason="The start completed; operator now authorizes a separate reboot",
                commands_stopped=True,
                resource_confirmed=True,
            )

            def reboot() -> None:
                close_old_connections()
                try:
                    result = NodeDeploymentService().reboot_node(
                        NodeDeployment.objects.get(pk=self.deployment.pk), {}, user=self.actor
                    )
                    self.assertTrue(result.is_ok(), result)
                    self.node.refresh_from_db()
                    observed.append(
                        (
                            self.node.status,
                            self.node.is_draining,
                            NodeMaintenanceExecution.objects.get(action="reboot").phase,
                        )
                    )
                finally:
                    connections.close_all()

            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(reboot).result(timeout=15)
            self.assertEqual(observed, [("active", True, "awaiting_recovery")])

        def after_activation(
            execute: Execute, sql: str, params: SQLParams, many: bool, context: Mapping[str, object]
        ) -> object:
            result = execute(sql, params, many, context)
            if (
                sql.startswith('UPDATE "provisioning_virtualmin_servers"')
                and params
                and "active" in params
                and "disabled" in params
            ):
                activation_updates.append(True)
                # Observe the actual write and wait for its genuine commit, never invent a lock/phase.
                transaction.on_commit(replace_with_reboot)
            return result

        with (
            patch("apps.infrastructure.deployment_service.run_provider_command") as provider,
            patch("apps.common.credential_vault.get_credential_vault") as vault,
            patch(
                "apps.provisioning.virtualmin_gateway.VirtualminGateway.test_connection",
                return_value=Ok({"healthy": True}),
            ),
            connection.execute_wrapper(after_activation),
        ):
            provider.return_value = Ok(ProviderCommandResult(True, "", "", 0, "fixture"))
            vault.return_value.get_credential.return_value = Ok(("praho-api", "fixture-only", {}))

            result = NodeDeploymentService().start_node(self.deployment, {}, user=self.actor)

        self.assertEqual(activation_updates, [True])
        self.assertEqual([call.kwargs["operation"] for call in provider.call_args_list], ["power_on", "reboot"])
        self.node.refresh_from_db()
        self.assertEqual((self.node.status, self.node.is_draining), ("active", True))
        self.assertTrue(result.is_err(), "A stale start cannot report successful drain reopening")
        self.assertEqual(NodeMaintenanceExecution.objects.get(action="reboot").phase, "awaiting_recovery")
