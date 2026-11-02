"""Existing queue helpers publish durable ownership and preserve the exact native claim."""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution
from apps.infrastructure.node_maintenance_tasks import tick_node_maintenance
from apps.infrastructure.provider_config import ProviderCommandResult
from apps.infrastructure.tasks import (
    queue_maintenance,
    queue_reboot_node,
    queue_start_node,
    queue_stop_node,
    queue_upgrade_node,
)
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(Q_CLUSTER={"name": "maintenance-native-queue", "orm": "default", "retry": 100000})
class NodeMaintenanceNativeQueueTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def deployment(self):
        deployment = _create_deployment("completed", external_node_id="queued-native-fixture")
        deployment.virtualmin_server = self.node
        deployment.save(update_fields=["virtualmin_server"])
        return deployment

    def test_all_native_queue_helpers_refuse_live_window_before_publication(self) -> None:
        deployment = self.deployment()
        self.start(self.window())
        calls = (
            lambda: queue_maintenance(deployment.pk, ["security"], user_id=self.actor.pk),
            lambda: queue_reboot_node(deployment.pk, deployment.provider_id, self.actor.pk),
            lambda: queue_stop_node(deployment.pk, deployment.provider_id, self.actor.pk),
            lambda: queue_start_node(deployment.pk, deployment.provider_id, self.actor.pk),
            lambda: queue_upgrade_node(deployment.pk, deployment.node_size_id, deployment.provider_id, self.actor.pk),
        )
        queued_before = set(OrmQ.objects.values_list("pk", flat=True))
        for call in calls:
            with self.subTest(call=call), self.assertRaises(ValidationError):
                call()
        self.assertEqual(set(OrmQ.objects.values_list("pk", flat=True)), queued_before)

    def test_queued_security_work_publishes_an_owner_and_runs_that_same_owner_once(self) -> None:
        deployment = self.deployment()
        task_id = queue_maintenance(deployment.pk, ["security"], user_id=self.actor.pk)
        task = next(row.task for row in OrmQ.objects.all() if row.task["id"] == task_id)
        self.assertGreaterEqual(task.get("timeout", 0), 1800, "The native leaf needs its actual playbook budget")
        execution = NodeMaintenanceExecution.objects.get(deployment=deployment)
        self.assertEqual((execution.phase, execution.q_task_id), ("claimed", task_id))
        with self.assertRaises(ValidationError):
            self.window()
        observations: list[tuple[bool, str]] = []

        def native_boundary(**_kwargs: object) -> Ok[AnsibleResult]:
            observations.append(
                (connection.in_atomic_block, NodeMaintenanceExecution.objects.get(pk=execution.pk).phase)
            )
            return Ok(AnsibleResult(True, "virtualmin_harden.yml", "", "", 0))

        with patch("apps.infrastructure.ansible_service.AnsibleService.run_playbook", side_effect=native_boundary):
            result = import_string(task["func"])(*task["args"], **task["kwargs"])
            replay = import_string(task["func"])(*task["args"], **task["kwargs"])
        self.assertTrue(result["success"], result)
        self.assertFalse(replay["success"], replay)
        self.assertEqual(observations, [(False, "issued")])
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "verified")

    def test_orm_enqueue_failure_leaves_no_native_reservation(self) -> None:
        deployment = self.deployment()
        with (
            patch("django_q.brokers.orm.ORM.enqueue", side_effect=RuntimeError("broker unavailable")),
            self.assertRaisesMessage(RuntimeError, "broker unavailable"),
        ):
            queue_maintenance(deployment.pk, ["security"], user_id=self.actor.pk)
        self.assertFalse(NodeMaintenanceExecution.objects.filter(deployment=deployment).exists())

    def test_public_staff_maintenance_reports_current_owner_instead_of_an_internal_error(self) -> None:
        deployment = self.deployment()
        self.start(self.window())
        self.client.force_login(self.actor)
        queued_before = set(OrmQ.objects.values_list("pk", flat=True))
        response = self.client.post(
            reverse("infrastructure:deployment_maintenance", args=[deployment.pk]), {"playbooks": ["security"]}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(set(OrmQ.objects.values_list("pk", flat=True)), queued_before)
        self.assertTrue(any("Maintenance" in str(message) for message in get_messages(response.wsgi_request)))

    def test_expired_unissued_claim_releases_without_replaying_a_late_payload(self) -> None:
        deployment = self.deployment()
        task_id = queue_maintenance(deployment.pk, ["security"], user_id=self.actor.pk)
        old_task = next(row.task for row in OrmQ.objects.all() if row.task["id"] == task_id)
        first = NodeMaintenanceExecution.objects.get(deployment=deployment)
        self.assertIsNotNone(first.lease_until)
        with patch("django.utils.timezone.now", return_value=first.lease_until + timedelta(seconds=1)):
            tick_node_maintenance()
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=first.pk).phase, "failed")
        new_id = queue_maintenance(deployment.pk, ["security"], user_id=self.actor.pk)
        current = NodeMaintenanceExecution.objects.exclude(pk=first.pk).get(deployment=deployment)
        with patch("apps.infrastructure.ansible_service.AnsibleService.run_playbook") as native:
            stale = import_string(old_task["func"])(*old_task["args"], **old_task["kwargs"])
        self.assertFalse(stale["success"], stale)
        native.assert_not_called()
        self.assertEqual((current.phase, current.q_task_id), ("claimed", new_id))
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=current.pk).phase, "claimed")

    def test_clock_expiry_never_releases_acknowledged_or_uncertain_native_work(self) -> None:
        deployment = self.deployment()
        with patch(
            "apps.infrastructure.deployment_service.run_provider_command",
            return_value=Ok(ProviderCommandResult(True, "", "", 0, "fixture")),
        ):
            result = _make_service().reboot_node(deployment, {}, user=self.actor)
        self.assertTrue(result.is_ok(), result)
        execution = NodeMaintenanceExecution.objects.get(deployment=deployment)
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(days=30)):
            tick_node_maintenance()
        self.assertEqual(NodeMaintenanceExecution.objects.get(pk=execution.pk).phase, "awaiting_recovery")
        with self.assertRaises(ValidationError):
            queue_maintenance(deployment.pk, ["security"], user_id=self.actor.pk)
