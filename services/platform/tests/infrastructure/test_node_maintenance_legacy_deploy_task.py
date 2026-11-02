"""A pre-reservation payload cannot terminalize a deployment owned by a newer queue."""

from django.test import TestCase, override_settings
from django_q.models import OrmQ

from apps.infrastructure.tasks import deploy_node_task, queue_deploy_node
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


@override_settings(Q_CLUSTER={"name": "maintenance-legacy-deploy", "orm": "default", "retry": 100000})
class NodeMaintenanceLegacyDeployTaskTests(TestCase):
    def test_a_genuine_unreserved_legacy_payload_still_fails_its_unstarted_row(self) -> None:
        deployment = _create_deployment()
        self.assertIsNone(deployment.operation_token)

        result = deploy_node_task(deployment.pk, deployment.provider_id + 1000)

        self.assertFalse(result["success"], result)
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")
        self.assertIsNone(deployment.operation_token)
        self.assertIsNone(deployment.operation_reserved_at)

    def test_the_current_token_payload_still_fails_its_own_unstarted_row(self) -> None:
        deployment = _create_deployment()
        queue_deploy_node(deployment.pk, deployment.provider_id)
        deployment.refresh_from_db()
        self.assertIsNotNone(deployment.operation_token)

        result = deploy_node_task(
            deployment.pk, deployment.provider_id + 1000, operation_token=str(deployment.operation_token)
        )

        self.assertFalse(result["success"], result)
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "failed")
        self.assertIsNone(deployment.operation_token)
        self.assertIsNone(deployment.operation_reserved_at)

    def test_a_legacy_missing_provider_payload_preserves_a_new_public_enqueue(self) -> None:
        deployment = _create_deployment()
        missing_provider_id = deployment.provider_id + 1000
        queued_before = set(OrmQ.objects.values_list("pk", flat=True))
        queue_deploy_node(deployment.pk, deployment.provider_id)
        deployment.refresh_from_db()
        reservation = (deployment.operation_token, deployment.operation_kind, deployment.operation_reserved_at)
        self.assertIsNotNone(reservation[0])
        self.assertIsNotNone(reservation[2])
        queued = OrmQ.objects.exclude(pk__in=queued_before)
        self.assertEqual(queued.count(), 1)
        self.assertEqual(queued.get().task["func"], "apps.infrastructure.tasks.deploy_node_task")
        self.assertEqual(queued.get().task["args"][-1], str(reservation[0]))
        queued_ids = set(OrmQ.objects.values_list("pk", flat=True))

        result = deploy_node_task(deployment.pk, missing_provider_id)

        self.assertFalse(result["success"], result)
        self.assertIn("Provider", result["error"])
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "pending", "A legacy payload terminalized a newer enqueue")
        self.assertEqual(
            (deployment.operation_token, deployment.operation_kind, deployment.operation_reserved_at), reservation
        )
        self.assertEqual(set(OrmQ.objects.values_list("pk", flat=True)), queued_ids)
