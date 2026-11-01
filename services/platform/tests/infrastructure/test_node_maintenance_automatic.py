"""Public scheduling publishes exact automatic ownership before native work."""

from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ

from apps.common.types import Err, Ok
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.infrastructure.node_maintenance_service import change_window, create_window
from apps.infrastructure.node_maintenance_tasks import tick_node_maintenance
from apps.infrastructure.provider_config import ProviderCommandResult
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(Q_CLUSTER={"name": "maintenance-automatic", "orm": "default", "retry": 100000})
class NodeMaintenanceAutomaticTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def automatic_window(self, *, due: bool = True, mode: str = "reboot") -> NodeMaintenanceWindow:
        deployment = _create_deployment("completed", external_node_id="automatic-native-fixture")
        deployment.virtualmin_server = self.node
        deployment.save(update_fields=["virtualmin_server"])
        starts = timezone.now() + (timedelta(seconds=-10) if due else timedelta(hours=2))
        return create_window(
            self.node.pk,
            actor=self.actor,
            kind="panel_update" if mode == "security" else "reboot",
            execution_mode=mode,
            starts_at=starts,
            ends_at=starts + timedelta(minutes=30),
            expects_downtime=mode == "reboot",
            expected_downtime_minutes=5 if mode == "reboot" else 0,
            customer_note="Approved restart maintenance.",
        )

    def test_security_hardening_requires_its_reviewed_workflow_and_a_manual_window(self) -> None:
        with self.assertRaisesMessage(ValidationError, "manual"):
            self.automatic_window(mode="security")
        self.assertFalse(NodeMaintenanceWindow.objects.exists())

    def test_an_unsupported_legacy_schedule_is_not_stranded_or_dispatched(self) -> None:
        # A compatibility fixture for the previous permissive mode; it grants no authority.
        starts = timezone.now() + timedelta(hours=2)
        policy = NodeMaintenancePolicy.objects.get(node=self.node)
        window = NodeMaintenanceWindow.objects.create(
            node=self.node,
            node_uuid=self.node.pk,
            policy=policy,
            policy_revision=policy.revision,
            policy_timezone="UTC",
            kind="panel_update",
            execution_mode="security",
            starts_at=starts,
            start_by=starts + timedelta(minutes=15),
            ends_at=starts + timedelta(minutes=30),
            customer_note="Previously scheduled work",
            created_by=self.actor,
        )
        with patch("apps.infrastructure.deployment_service.run_provider_command") as native:
            result = tick_node_maintenance([str(window.pk)])
        self.assertEqual(result["not_run"], 1)
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "failed")
        self.assertFalse(window.executions.exists())
        native.assert_not_called()

    def leaf(self) -> dict[str, object]:
        rows = [
            row.task
            for row in OrmQ.objects.all()
            if row.task["func"] == "apps.infrastructure.node_maintenance_tasks.execute_window"
        ]
        self.assertEqual(len(rows), 1, "Publish exactly one supported automatic leaf through the normal ORM broker")
        return rows[0]

    def test_a_due_tick_claims_and_queues_one_exact_revision_without_native_io(self) -> None:
        window = self.automatic_window()
        with patch("apps.infrastructure.ansible_service.AnsibleService.run_playbook") as native:
            result = tick_node_maintenance([str(window.pk)])
            tick_node_maintenance([str(window.pk)])
        self.assertEqual(result["queued"], 1)
        current = NodeMaintenanceWindow.objects.get(pk=window.pk)
        self.assertEqual(current.status, "running")
        execution = NodeMaintenanceExecution.objects.get(pk=current.current_execution_id)
        self.assertEqual(execution.phase, "claimed")
        self.assertEqual(execution.deployment.virtualmin_server_id, window.node_id)
        self.assertEqual(execution.provider_resource_id, "automatic-native-fixture")
        self.assertEqual(tuple(self.leaf()["args"]), (str(window.pk), window.revision, str(execution.token)))
        self.assertGreaterEqual(
            self.leaf().get("timeout", 0), 1800, "The queue must allow the actual supported playbook budget"
        )
        native.assert_not_called()

    def test_actual_reboot_leaf_runs_once_then_requires_operator_recovery_attestation(self) -> None:
        window = self.automatic_window()
        self.start(window)
        task = self.leaf()
        leaf = import_string(task["func"])
        observed: list[tuple[bool, str]] = []

        def native_boundary(**_kwargs: object) -> Ok[ProviderCommandResult]:
            execution = NodeMaintenanceExecution.objects.get(window=window)
            observed.append((connection.in_atomic_block, execution.phase))
            return Ok(ProviderCommandResult(True, "", "", 0, "fixture"))

        with (
            patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("fixture-only")),
            patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=native_boundary),
        ):
            first = leaf(*task["args"])
            second = leaf(*task["args"])
        self.assertTrue(first["success"], first)
        self.assertFalse(second["success"], "An already issued or settled job must never replay")
        self.assertEqual(observed, [(False, "issued")])
        current = NodeMaintenanceWindow.objects.get(pk=window.pk)
        self.assertEqual((current.status, current.completion_source), ("running", ""))
        self.assertEqual(NodeMaintenanceExecution.objects.get(window=window).phase, "awaiting_recovery")
        settled = change_window(
            window.pk,
            actor=self.actor,
            revision=window.revision,
            action="finish",
            reason="Recovery checked",
            outcome="completed",
            public_outcome="The operator checked recovery.",
            attestation=True,
        )
        self.assertEqual((settled.status, settled.completion_source), ("completed", "operator"))
        self.assertEqual(NodeMaintenanceExecution.objects.get(window=window).phase, "verified")

    def test_a_missed_latest_start_is_truthfully_not_run_without_issuing_work(self) -> None:
        window = self.automatic_window()
        with patch("django.utils.timezone.now", return_value=window.start_by + timedelta(seconds=1)):
            result = tick_node_maintenance([str(window.pk)])
        self.assertEqual(result["not_run"], 1)
        current = NodeMaintenanceWindow.objects.get(pk=window.pk)
        self.assertEqual(current.status, "failed")
        self.assertIsNone(current.started_at)
        self.assertIn("did not run", current.public_outcome)
        self.assertFalse(current.executions.exists())
        self.assertFalse(OrmQ.objects.filter(key="maintenance-automatic").exists())

    def test_broker_failure_rolls_back_automatic_start_and_execution_together(self) -> None:
        window = self.automatic_window()
        with (
            patch("django_q.brokers.orm.ORM.enqueue", side_effect=RuntimeError("broker unavailable")),
            self.assertRaisesMessage(RuntimeError, "broker unavailable"),
        ):
            self.start(window)
        current = NodeMaintenanceWindow.objects.get(pk=window.pk)
        self.assertEqual(current.status, "scheduled")
        self.assertIsNone(current.current_execution_id)
        self.assertFalse(current.executions.exists())

    def test_zero_deferral_must_be_reviewed_before_automatic_scheduling(self) -> None:
        policy = NodeMaintenancePolicy.objects.get(node=self.node)
        policy.max_defer_minutes = 0
        policy.save()
        with self.assertRaisesMessage(ValidationError, "at least one minute"):
            self.automatic_window()
        self.assertFalse(NodeMaintenanceWindow.objects.exists())

    def test_a_duplicate_arriving_during_native_io_cannot_change_the_issued_owner(self) -> None:
        window = self.automatic_window()
        self.start(window)
        task = self.leaf()
        leaf = import_string(task["func"])
        seen: list[tuple[bool, str]] = []

        def native_boundary(**_kwargs: object) -> Ok[ProviderCommandResult]:
            duplicate = leaf(*task["args"])
            seen.append((duplicate["success"], NodeMaintenanceExecution.objects.get(window=window).phase))
            return Ok(ProviderCommandResult(True, "", "", 0, "fixture"))

        with (
            patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("fixture-only")),
            patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=native_boundary),
        ):
            result = leaf(*task["args"])
        self.assertTrue(result["success"], result)
        self.assertEqual(seen, [(False, "issued")])
        self.assertEqual(NodeMaintenanceExecution.objects.get(window=window).phase, "awaiting_recovery")

    def test_an_issued_failed_provider_response_remains_held_and_is_never_replayed(self) -> None:
        window = self.automatic_window()
        self.start(window)
        task = self.leaf()
        leaf = import_string(task["func"])
        with (
            patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("fixture-only")),
            patch(
                "apps.infrastructure.deployment_service.run_provider_command", return_value=Err("Lost native response")
            ) as native,
        ):
            first = leaf(*task["args"])
            duplicate = leaf(*task["args"])
        self.assertFalse(first["success"], first)
        self.assertFalse(duplicate["success"], duplicate)
        self.assertEqual(native.call_count, 1)
        self.assertEqual(NodeMaintenanceExecution.objects.get(window=window).phase, "uncertain")
        self.assertEqual(NodeMaintenanceWindow.objects.get(pk=window.pk).status, "running")

    def test_reboot_acceptance_never_claims_verified_recovery(self) -> None:
        deployment = _create_deployment("completed", external_node_id="automatic-reboot-fixture")
        deployment.virtualmin_server = self.node
        deployment.save(update_fields=["virtualmin_server"])
        starts = timezone.now() - timedelta(seconds=10)
        window = create_window(
            self.node.pk,
            actor=self.actor,
            kind="reboot",
            execution_mode="reboot",
            starts_at=starts,
            ends_at=starts + timedelta(minutes=30),
            expects_downtime=True,
            expected_downtime_minutes=5,
            customer_note="An approved restart.",
        )
        self.start(window)
        task = self.leaf()
        with (
            patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("fixture-only")),
            patch(
                "apps.infrastructure.deployment_service.run_provider_command",
                return_value=Ok(ProviderCommandResult(True, "", "", 0, "fixture")),
            ),
        ):
            result = import_string(task["func"])(*task["args"])
        self.assertTrue(result["success"], result)
        self.assertEqual(NodeMaintenanceExecution.objects.get(window=window).phase, "awaiting_recovery")
        current = NodeMaintenanceWindow.objects.get(pk=window.pk)
        self.assertEqual((current.status, current.completion_source, current.finished_at), ("running", "", None))
