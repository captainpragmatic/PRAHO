"""Retention completes before teardown, and retries retain exact dependency IDs after the VM is gone."""

import uuid
from unittest.mock import Mock, patch

from django.test import TestCase
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.cloud_destroy_execution import ResourceDestroyExecution
from apps.infrastructure.cloud_destroy_models import CloudResourceCleanup, CloudResourceRetention
from apps.infrastructure.cloud_destroy_service import (
    DestroyApproval,
    approve_destroy,
    inspect_destroy,
    record_resource_ownership,
)
from apps.infrastructure.cloud_resource_inventory import CAPABILITIES, CloudResource
from apps.infrastructure.deployment_lifecycle import claim_operation, provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeServerLifetime
from apps.users.models import User
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class ResourceExecutionTests(TestCase):
    def test_confirmed_vm_absence_ends_billing_even_when_dependency_cleanup_stops(self):
        self.resources.append(CloudResource("firewall", "f", attached_to=("vm",)))
        record_resource_ownership(self.deployment, "firewall", "f", "create_response")
        for identifier in ("vm", ""):
            NodeServerLifetime.objects.create(
                deployment=self.deployment,
                correlation_id=self.deployment.correlation_id,
                server_id=identifier,
                node_size=self.deployment.node_size,
                monthly_cost_eur=3,
                started_at=timezone.now(),
            )
        execution = self.execution("delete")
        self.assertTrue(execution.prepare().is_ok())

        def delete(kind, resource_id):
            return Err("firewall permission denied") if kind == "firewall" else self.delete(kind, resource_id)

        self.client.delete_exact.side_effect = delete
        self.assertTrue(execution.delete_resources().is_err())
        self.assertEqual([row.resource_id for row in self.resources], ["f"])
        self.assertFalse(self.deployment.server_lifetimes.filter(ended_at__isnull=True).exists())

    def setUp(self):
        self.deployment = _create_deployment("completed", external_node_id="vm")
        self.deployment.provider_token_fingerprint = provider_token_fingerprint("token")
        self.deployment.server_create_state = "created"
        self.deployment.save(update_fields=["provider_token_fingerprint", "server_create_state"])
        self.actor = User.objects.create_superuser(email="destroy-worker@example.test", password="test-only")
        self.client = Mock(capabilities=CAPABILITIES["hetzner"])
        self.resources = [CloudResource("server", "vm")]
        self.client.inventory.side_effect = lambda _ids: Ok(list(self.resources))
        self.client.read_exact.side_effect = self.read
        self.client.delete_exact.side_effect = self.delete
        self.patch = patch("apps.infrastructure.cloud_destroy_service.get_cloud_gateway")
        self.factory = self.patch.start()
        self.factory.return_value.resource_client.return_value = self.client
        self.addCleanup(self.patch.stop)

    def read(self, kind, resource_id):
        resource = next((row for row in self.resources if row.kind == kind and row.resource_id == resource_id), None)
        return {"id": resource_id, "type": kind, "status": resource.state or "available"} if resource else None

    def delete(self, kind, resource_id):
        self.resources[:] = [row for row in self.resources if (row.kind, row.resource_id) != (kind, resource_id)]
        return Ok(True)

    def execution(self, policy="keep"):
        preview = inspect_destroy(self.deployment, "token")
        self.plan = approve_destroy(
            self.deployment,
            "token",
            self.actor,
            DestroyApproval(self.deployment.hostname, preview.digest, policy, "Explicit restore-point responsibility"),
        )
        self.lease = claim_operation(
            self.deployment.pk, from_states=("completed",), to_status="destroying", kind="destroy"
        ).unwrap()
        self.deployment.refresh_from_db()
        return ResourceDestroyExecution(self.deployment, self.lease, self.plan, self.client, "token")

    def test_failed_backup_conversion_blocks_all_provider_deletion(self):
        self.resources.append(CloudResource("backup", "b", source_ids=("vm",), state="available"))
        execution = self.execution()
        self.client.retain_backup.return_value = Err("conversion pending")
        self.assertTrue(execution.prepare().is_err())
        self.client.delete_exact.assert_not_called()
        self.assertEqual(CloudResourceCleanup.objects.get(plan=self.plan, resource_id="b").state, "unresolved")

    def test_missing_intentionally_kept_snapshot_blocks_teardown_even_after_approval(self):
        self.resources.append(CloudResource("snapshot", "s", source_ids=("vm",), state="available"))
        execution = self.execution()
        self.resources.pop()
        self.assertTrue(execution.prepare().is_err())
        self.client.delete_exact.assert_not_called()

    def test_accepted_conversion_is_rechecked_for_a_durable_ready_snapshot(self):
        self.resources.append(CloudResource("backup", "b", source_ids=("vm",), state="available"))
        execution = self.execution()
        self.client.retain_backup.return_value = Ok("b")
        self.assertTrue(
            execution.prepare().is_err(), "A conversion receipt cannot replace durable snapshot verification"
        )
        self.client.delete_exact.assert_not_called()

    def test_successful_conversion_is_persisted_and_drift_expiry_is_suppressed(self):
        self.resources.append(CloudResource("backup", "b", source_ids=("vm",), state="available"))
        execution = self.execution()

        def convert(_backup_id):
            self.resources[-1] = CloudResource("snapshot", "b", source_ids=("vm",), state="available")
            return Ok("b")

        self.client.retain_backup.side_effect = convert
        self.assertTrue(execution.prepare().is_ok())
        outcome = CloudResourceCleanup.objects.get(plan=self.plan, resource_id="b")
        self.assertEqual((outcome.state, outcome.durable_snapshot_id), ("retained", "b"))
        self.assertTrue(
            CloudResourceRetention.objects.filter(plan=self.plan, kind="snapshot", resource_id="b").exists()
        )

    def test_changed_lease_refuses_before_provider_io(self):
        execution = self.execution()
        self.client.reset_mock()
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(operation_token=uuid.uuid4())
        self.assertTrue(execution.prepare().is_err())
        self.client.inventory.assert_not_called()
        self.client.delete_exact.assert_not_called()

    def test_new_backup_after_approval_requires_new_review(self):
        execution = self.execution("delete")
        self.resources.append(CloudResource("backup", "new", source_ids=("vm",), state="available"))
        self.assertTrue(execution.prepare().is_err())
        self.client.delete_exact.assert_not_called()

    def _assert_new_consumer_preserved(self, kind, *, after_prepare):
        if kind == "volume_snapshot":
            self.resources.append(CloudResource("volume", "owned-volume", attached_to=("vm",)))
            record_resource_ownership(self.deployment, "volume", "owned-volume", "create_response")
            source = "owned-volume"
            consumer = CloudResource("volume", "unrelated-volume", source_ids=("shared-point",))
        else:
            source = "vm"
            consumer = CloudResource("server", "unrelated-vm", source_ids=("shared-point",))
        self.resources.append(CloudResource(kind, "shared-point", source_ids=(source,), state="available"))
        execution = self.execution("delete")
        if after_prepare:
            self.assertTrue(execution.prepare().is_ok())
        self.resources.append(consumer)
        expected = list(self.resources)
        result = execution.delete_resources() if after_prepare else execution.prepare()
        self.assertTrue(result.is_err(), "A newly shared restore point requires a new review")
        self.client.delete_exact.assert_not_called()
        self.assertEqual(self.resources, expected)

    def test_snapshot_shared_after_approval_blocks_all_deletion(self):
        self._assert_new_consumer_preserved("snapshot", after_prepare=False)

    def test_snapshot_shared_after_prepare_blocks_all_deletion(self):
        self._assert_new_consumer_preserved("snapshot", after_prepare=True)

    def test_volume_snapshot_shared_after_approval_blocks_all_deletion(self):
        self._assert_new_consumer_preserved("volume_snapshot", after_prepare=False)

    def test_volume_snapshot_shared_after_prepare_blocks_all_deletion(self):
        self._assert_new_consumer_preserved("volume_snapshot", after_prepare=True)

    def test_unowned_auto_deleted_primary_ip_blocks_vm_deletion(self):
        self.resources.append(CloudResource("primary_ip", "ip", attached_to=("vm",), auto_delete=True))
        execution = self.execution("delete")
        self.assertTrue(execution.prepare().is_err())
        self.client.delete_exact.assert_not_called()

    def test_conversion_receipt_lost_before_database_write_can_resume(self):
        self.resources.append(CloudResource("backup", "b", source_ids=("vm",), state="available"))
        execution = self.execution()
        self.resources[-1] = CloudResource("snapshot", "b", source_ids=("vm",), state="available")
        self.client.retain_backup.return_value = Ok("b")
        self.assertTrue(execution.prepare().is_ok())
        self.assertEqual(CloudResourceCleanup.objects.get(plan=self.plan, resource_id="b").state, "retained")

    def test_retained_snapshot_is_rechecked_immediately_before_vm_deletion(self):
        self.resources.append(CloudResource("snapshot", "s", source_ids=("vm",), state="available"))
        execution = self.execution()
        self.assertTrue(execution.prepare().is_ok())
        self.resources.pop()
        self.assertTrue(execution.delete_resources().is_err())
        self.client.delete_exact.assert_not_called()

    def test_cleanup_retries_exact_dependency_ids_after_vm_identifier_is_cleared(self):
        self.resources.append(CloudResource("firewall", "f", attached_to=("vm",)))
        record_resource_ownership(self.deployment, "firewall", "f", "create_response")
        execution = self.execution("delete")
        self.assertTrue(execution.prepare().is_ok())
        failed = False

        def delete_with_failure(kind, resource_id):
            nonlocal failed
            if kind == "firewall" and not failed:
                failed = True
                return Err("provider timeout")
            return self.delete(kind, resource_id)

        self.client.delete_exact.side_effect = delete_with_failure
        self.assertTrue(execution.delete_resources().is_err())
        self.assertEqual([row.resource_id for row in self.resources], ["f"])
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(external_node_id="")
        self.deployment.refresh_from_db()
        retry = ResourceDestroyExecution(self.deployment, self.lease, self.plan, self.client, "token")
        self.assertTrue(retry.prepare().is_ok())
        self.assertTrue(retry.delete_resources().is_ok())
        self.assertEqual(self.resources, [])
        self.assertEqual(
            [call.args for call in self.client.delete_exact.call_args_list],
            [("server", "vm"), ("firewall", "f"), ("firewall", "f")],
        )
