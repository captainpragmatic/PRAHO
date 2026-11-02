"""A queued lifecycle reservation is a real owner; historical operation tokens are not."""

from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from apps.infrastructure.deployment_lifecycle import claim_operation, reserve_operation
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.node_teardown import close_node_admission
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.infrastructure.tasks import queue_destroy_node
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(Q_CLUSTER={"name": "maintenance-deployment", "orm": "default", "retry": 100000})
class NodeMaintenanceDeploymentAdmissionTests(MaintenanceAdmissionFixture, TestCase):
    def deployment(self) -> NodeDeployment:
        deployment = _create_deployment("completed")
        deployment.virtualmin_server = self.node
        deployment.save(update_fields=["virtualmin_server"])
        return deployment

    def test_a_running_window_refuses_a_public_deployment_reservation(self) -> None:
        deployment = self.deployment()
        self.start(self.window())

        result = reserve_operation(deployment.pk, from_states=("completed",), kind="destroy")

        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertIsNone(NodeDeployment.objects.get(pk=deployment.pk).operation_token)

    def test_a_preclaim_reservation_blocks_window_start_even_in_completed_status(self) -> None:
        deployment = self.deployment()
        window = self.window()
        reservation = reserve_operation(deployment.pk, from_states=("completed",), kind="destroy")
        self.assertTrue(reservation.is_ok())

        with self.assertRaisesMessage(ValidationError, "deployment operation"):
            self.start(window)

        self.assertEqual(NodeDeployment.objects.get(pk=deployment.pk).status, "completed")

    def test_broker_failure_rolls_back_the_exact_reservation(self) -> None:
        deployment = self.deployment()
        previous_token = deployment.operation_token
        with (
            patch("django_q.tasks.async_task", side_effect=RuntimeError("owned broker unavailable")),
            self.assertRaises(RuntimeError),
        ):
            queue_destroy_node(deployment.pk, deployment.provider_id)

        current = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual(current.operation_token, previous_token)
        self.assertIsNone(current.operation_reserved_at)

    def test_a_successful_claim_clears_only_its_preclaim_marker(self) -> None:
        deployment = self.deployment()
        reservation = reserve_operation(deployment.pk, from_states=("completed",), kind="destroy").unwrap()
        self.assertIsNotNone(NodeDeployment.objects.get(pk=deployment.pk).operation_reserved_at)

        claimed = claim_operation(
            deployment.pk,
            from_states=("completed",),
            to_status="destroying",
            kind="destroy",
            expected_token=reservation,
        )

        self.assertTrue(claimed.is_ok())
        self.assertIsNone(NodeDeployment.objects.get(pk=deployment.pk).operation_reserved_at)

    def test_a_stale_claim_preserves_the_newer_reservation(self) -> None:
        deployment = self.deployment()
        stale = reserve_operation(deployment.pk, from_states=("completed",), kind="destroy").unwrap()
        latest = reserve_operation(deployment.pk, from_states=("completed",), kind="destroy").unwrap()

        refused = claim_operation(
            deployment.pk, from_states=("completed",), to_status="destroying", kind="destroy", expected_token=stale
        )

        self.assertTrue(refused.is_err())
        current = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertEqual(current.operation_token, latest)
        self.assertIsNotNone(current.operation_reserved_at)

    def test_terminal_refusal_settles_only_its_exact_unissued_reservation(self) -> None:
        deployment = self.deployment()
        token = reserve_operation(deployment.pk, from_states=("completed",), kind="destroy").unwrap()
        deployment.refresh_from_db()
        deployment.transition_to("stopped")

        refused = claim_operation(
            deployment.pk, from_states=("completed",), to_status="destroying", kind="destroy", expected_token=token
        )

        self.assertTrue(refused.is_err())
        current = NodeDeployment.objects.get(pk=deployment.pk)
        self.assertIsNone(current.operation_reserved_at)
        self.assertIsNone(current.operation_token)

    def test_even_an_empty_nodes_running_window_blocks_direct_teardown_admission(self) -> None:
        self.account.delete()
        self.start(self.window())

        result = close_node_admission(self.node.pk)

        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.node.refresh_from_db()
        self.assertEqual(self.node.status, "active")

    def test_direct_unregister_preserves_the_running_window_and_server_binding(self) -> None:
        deployment = self.deployment()
        self.start(self.window())

        result = NodeRegistrationService().unregister_node(deployment, delete_server=False, user=self.actor)

        self.assertTrue(result.is_err())
        self.assertIn("Maintenance", result.unwrap_err())
        self.assertEqual(NodeDeployment.objects.get(pk=deployment.pk).virtualmin_server_id, self.node.pk)
