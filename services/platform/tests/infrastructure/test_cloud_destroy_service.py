"""Review and execution are bound to the exact creating credential and resource manifest."""

from unittest.mock import Mock, patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.common.types import Err, Ok
from apps.infrastructure.cloud_destroy_models import CloudResourceRetention, NodeDestroyPlan
from apps.infrastructure.cloud_destroy_service import DestroyApproval, approve_destroy, inspect_destroy
from apps.infrastructure.cloud_resource_inventory import CAPABILITIES, CloudResource
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.users.models import User
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class DestroyApprovalTests(TestCase):
    def setUp(self):
        self.deployment = _create_deployment("completed", external_node_id="vm")
        self.deployment.provider_token_fingerprint = provider_token_fingerprint("token")
        self.deployment.server_create_state = "created"
        self.deployment.save(update_fields=["provider_token_fingerprint", "server_create_state"])
        self.actor = User.objects.create_superuser(email="destroy-approver@example.test", password="test-only")
        self.resources = [
            CloudResource("server", "vm"),
            CloudResource("snapshot", "s", source_ids=("vm",), state="available"),
        ]
        self.cloud_client = Mock(capabilities=CAPABILITIES["hetzner"])
        self.cloud_client.inventory.return_value = Ok(self.resources)
        self.gateway = Mock()
        self.gateway.resource_client.return_value = self.cloud_client
        self.patch = patch("apps.infrastructure.cloud_destroy_service.get_cloud_gateway", return_value=self.gateway)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def approval(self, digest):
        return DestroyApproval(self.deployment.hostname, digest, "keep", "Keep the existing restore points")

    def test_inventory_permissions_are_not_treated_as_no_restore_points(self):
        self.cloud_client.inventory.return_value = Err("missing image permission")
        with self.assertRaisesRegex(ValidationError, "inventory"):
            inspect_destroy(self.deployment, "token")
        self.assertFalse(NodeDestroyPlan.objects.exists())
        self.gateway.delete_server.assert_not_called()

    def test_approval_rechecks_inventory_before_persisting_any_decision(self):
        preview = inspect_destroy(self.deployment, "token")
        self.cloud_client.inventory.return_value = Ok(
            [*self.resources, CloudResource("backup", "new", source_ids=("vm",))]
        )
        with self.assertRaisesRegex(ValidationError, "changed"):
            approve_destroy(self.deployment, "token", self.actor, self.approval(preview.digest))
        self.assertFalse(NodeDestroyPlan.objects.exists())
        self.assertFalse(CloudResourceRetention.objects.exists())

    def test_approval_records_exact_actor_choices_and_protects_intentionally_kept_snapshot(self):
        preview = inspect_destroy(self.deployment, "token")
        plan = approve_destroy(self.deployment, "token", self.actor, self.approval(preview.digest))
        self.assertEqual(plan.actor_id, self.actor.pk)
        self.assertEqual(plan.server_ids, ["vm"])
        self.assertEqual(
            {f"{row['kind']}:{row['resource_id']}": row["action"] for row in plan.decisions},
            {"server:vm": "delete", "snapshot:s": "keep"},
        )
        self.assertTrue(CloudResourceRetention.objects.filter(plan=plan, resource_id="s").exists())
        approval_event = AuditEvent.objects.get(action="configuration_changed", object_id=str(plan.pk))
        self.assertEqual(approval_event.user_id, self.actor.pk)
        self.assertEqual(approval_event.new_values["digest"], plan.digest)
        retention = CloudResourceRetention.objects.get(plan=plan, resource_id="s")
        self.assertTrue(AuditEvent.objects.filter(action="configuration_changed", object_id=str(retention.pk)).exists())
        ownership = self.deployment.resource_ownership.get(kind="server", resource_id="vm")
        self.assertTrue(AuditEvent.objects.filter(action="configuration_changed", object_id=str(ownership.pk)).exists())
        self.cloud_client.delete_exact.assert_not_called()
        self.cloud_client.retain_backup.assert_not_called()

    def test_permission_is_checked_before_provider_discovery(self):
        self.actor.is_superuser = False
        with self.assertRaises(PermissionDenied):
            approve_destroy(self.deployment, "token", self.actor, self.approval("b" * 64))
        self.gateway.resource_client.assert_not_called()

    def test_credential_identity_change_refuses_before_provider_io(self):
        with self.assertRaisesRegex(ValidationError, "credential"):
            inspect_destroy(self.deployment, "replacement")
        self.gateway.resource_client.assert_not_called()

    def test_hostname_confirmation_is_rechecked_in_the_service(self):
        preview = inspect_destroy(self.deployment, "token")
        approval = DestroyApproval("another-host", preview.digest, "delete", "Delete provider restore points")
        with self.assertRaisesRegex(ValidationError, "hostname"):
            approve_destroy(self.deployment, "token", self.actor, approval)
        self.assertFalse(NodeDestroyPlan.objects.exists())

    @patch("apps.infrastructure.views.get_provider_token", return_value=Ok("token"))
    @patch("apps.infrastructure.views.queue_destroy_node", return_value="task")
    def test_page_displays_exact_resources_and_retention_impact_without_queuing(self, queue, _token):
        self.client.force_login(self.actor)
        response = self.client.get(reverse("infrastructure:deployment_destroy", args=[self.deployment.pk]))
        self.assertContains(response, "Provider backups and snapshots")
        self.assertContains(response, "snapshot:s")
        self.assertContains(response, "charges continue")
        queue.assert_not_called()
        self.assertFalse(NodeDestroyPlan.objects.exists())

    @patch("apps.infrastructure.views.get_provider_token", return_value=Ok("token"))
    @patch("apps.infrastructure.views.queue_destroy_node", return_value="task")
    def test_post_cannot_queue_without_explicit_provider_retention_choice(self, queue, _token):
        self.client.force_login(self.actor)
        response = self.client.post(
            reverse("infrastructure:deployment_destroy", args=[self.deployment.pk]),
            {"confirm_hostname": self.deployment.hostname},
        )
        self.assertEqual(response.status_code, 200)
        queue.assert_not_called()
        self.assertFalse(NodeDestroyPlan.objects.exists())

    @patch("apps.infrastructure.views.get_provider_token", return_value=Ok("token"))
    @patch("apps.infrastructure.views.queue_destroy_node", return_value="task")
    def test_post_queues_the_exact_immutable_approval_id(self, queue, _token):
        self.client.force_login(self.actor)
        preview = inspect_destroy(self.deployment, "token")
        response = self.client.post(
            reverse("infrastructure:deployment_destroy", args=[self.deployment.pk]),
            {
                "confirm_hostname": self.deployment.hostname,
                "resource_digest": preview.digest,
                "provider_restore_points": "keep",
                "retention_reason": "Retain the existing snapshot",
                "accepted_provider_impact": "on",
            },
        )
        self.assertEqual(response.status_code, 302)
        plan = NodeDestroyPlan.objects.get(deployment=self.deployment)
        self.assertEqual(queue.call_args.kwargs["plan_id"], str(plan.pk))

    def vultr_backup(self):
        self.deployment.provider.provider_type = "vultr"
        self.deployment.provider.save(update_fields=["provider_type"])
        self.cloud_client.capabilities = CAPABILITIES["vultr"]
        self.resources[:] = [
            CloudResource("server", "vm"),
            CloudResource("backup", "b", source_ids=("vm",), state="complete"),
            CloudResource("snapshot", "converted", state="complete"),
        ]

    def test_keep_requires_console_preparation_when_backup_conversion_is_unsupported(self):
        self.vultr_backup()
        preview = inspect_destroy(self.deployment, "token")
        with self.assertRaisesRegex(ValidationError, "snapshot mapping"):
            approve_destroy(self.deployment, "token", self.actor, self.approval(preview.digest))
        self.assertFalse(NodeDestroyPlan.objects.exists())

    def test_console_backup_snapshot_mapping_is_immutable_and_tracks_original_backup_expiry(self):
        self.vultr_backup()
        preview = inspect_destroy(self.deployment, "token")
        approval = DestroyApproval(
            self.deployment.hostname,
            preview.digest,
            "keep",
            "I converted this exact backup to the prepared snapshot in the provider console",
            {"b": "converted"},
        )
        plan = approve_destroy(self.deployment, "token", self.actor, approval)
        self.assertEqual(plan.retention_mappings, {"b": "converted"})
        actions = {f"{row['kind']}:{row['resource_id']}": row["action"] for row in plan.decisions}
        self.assertEqual(actions["backup:b"], "await_expiry")
        self.assertEqual(actions["snapshot:converted"], "keep")
        self.assertTrue(CloudResourceRetention.objects.filter(plan=plan, resource_id="converted").exists())

    def test_mapping_cannot_claim_a_missing_or_pending_snapshot_is_durable(self):
        self.vultr_backup()
        for target in ("missing", "converted"):
            self.resources[-1] = CloudResource("snapshot", "converted", state="pending")
            preview = inspect_destroy(self.deployment, "token")
            approval = DestroyApproval(
                self.deployment.hostname, preview.digest, "keep", "Console preparation", {"b": target}
            )
            with self.subTest(target=target), self.assertRaises(ValidationError):
                approve_destroy(self.deployment, "token", self.actor, approval)
        self.assertFalse(NodeDestroyPlan.objects.exists())
