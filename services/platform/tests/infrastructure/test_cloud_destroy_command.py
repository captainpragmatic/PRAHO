"""The CLI uses the same explicit provider retention approval as the staff page."""

from io import StringIO
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.common.types import Ok
from apps.infrastructure.cloud_destroy_models import NodeDestroyPlan
from apps.infrastructure.cloud_resource_inventory import CAPABILITIES, CloudResource
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.users.models import User
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class DestroyCommandTests(TestCase):
    def setUp(self):
        self.deployment = _create_deployment("completed", external_node_id="vm")
        self.deployment.server_create_state = "created"
        self.deployment.provider_token_fingerprint = provider_token_fingerprint("token")
        self.deployment.save(update_fields=["server_create_state", "provider_token_fingerprint"])
        self.operator = User.objects.create_superuser(email="command-operator@example.test", password="test-only")
        self.cloud_client = Mock(capabilities=CAPABILITIES["hetzner"])
        self.cloud_client.inventory.return_value = Ok(
            [CloudResource("server", "vm"), CloudResource("snapshot", "s", source_ids=("vm",), state="available")]
        )
        factory = patch("apps.infrastructure.cloud_destroy_service.get_cloud_gateway").start()
        factory.return_value.resource_client.return_value = self.cloud_client
        self.addCleanup(patch.stopall)
        patch(
            "apps.infrastructure.management.commands.manage_node.get_provider_token", return_value=Ok("token")
        ).start()
        self.service = Mock()
        self.service.destroy_node.return_value = Ok(True)
        patch("apps.infrastructure.deployment_service.get_deployment_service", return_value=self.service).start()

    def test_force_does_not_choose_backup_retention_implicitly(self):
        with self.assertRaisesRegex(CommandError, "provider-restore-points"):
            call_command("manage_node", self.deployment.hostname, "destroy", "--force", stdout=StringIO())
        self.service.destroy_node.assert_not_called()
        self.assertFalse(NodeDestroyPlan.objects.exists())

    def test_dry_run_lists_exact_resources_and_both_retention_outcomes(self):
        output = StringIO()
        call_command("manage_node", self.deployment.hostname, "destroy", "--dry-run", stdout=output)
        self.assertIn("snapshot:s", output.getvalue())
        self.assertIn("charges continue", output.getvalue())
        self.service.destroy_node.assert_not_called()
        self.assertFalse(NodeDestroyPlan.objects.exists())

    def test_force_with_explicit_choices_passes_the_immutable_plan_to_the_service(self):
        call_command(
            "manage_node",
            self.deployment.hostname,
            "destroy",
            "--force",
            "--provider-restore-points",
            "keep",
            "--operator",
            self.operator.email,
            "--reason",
            "Retain the existing snapshot",
            "--accept-provider-impact",
            stdout=StringIO(),
        )
        plan = NodeDestroyPlan.objects.get(deployment=self.deployment)
        self.assertEqual(plan.restore_point_policy, "keep")
        self.assertEqual(self.service.destroy_node.call_args.kwargs["plan_id"], plan.pk)
        self.assertEqual(self.service.destroy_node.call_args.kwargs["user"], self.operator)
