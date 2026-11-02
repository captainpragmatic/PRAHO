"""The shared teardown secures provider restore points before unregistering or withdrawing DNS."""

from unittest.mock import Mock, patch

from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.cloud_destroy_models import CloudResourceCleanup
from apps.infrastructure.cloud_destroy_service import DestroyApproval, approve_destroy, inspect_destroy
from apps.infrastructure.cloud_resource_inventory import CAPABILITIES, CloudResource
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.node_teardown import NodeTeardown, claim_teardown
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.users.models import User
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class SharedCloudTeardownTests(TestCase):
    def setUp(self):
        self.deployment = _create_deployment("completed", external_node_id="vm")
        server = VirtualminServer.objects.create(
            name="cloud-teardown",
            hostname="cloud.example.test",
            api_username="praho-api",
            encrypted_api_password=b"",
            status="active",
        )
        self.deployment.virtualmin_server = server
        self.deployment.server_create_state = "created"
        self.deployment.provider_token_fingerprint = provider_token_fingerprint("token")
        self.deployment.save(update_fields=["virtualmin_server", "server_create_state", "provider_token_fingerprint"])
        self.actor = User.objects.create_superuser(email="cloud-destroy@example.test", password="test-only")
        self.resources = [
            CloudResource("server", "vm"),
            CloudResource("backup", "b", source_ids=("vm",), state="available"),
        ]
        self.client = Mock(capabilities=CAPABILITIES["hetzner"])
        self.client.inventory.side_effect = lambda _ids: Ok(list(self.resources))
        self.client.read_exact.side_effect = lambda kind, rid: (
            {"id": rid, "type": kind, "status": "available"}
            if any(row.kind == kind and row.resource_id == rid for row in self.resources)
            else None
        )
        self.gateway = Mock()
        self.gateway.resource_client.return_value = self.client
        self.gateway.find_servers_by_label.return_value = Ok([])
        self.gateway.find_firewalls_by_label.return_value = Ok([])
        self.gateway.find_ssh_keys_by_label.return_value = Ok([])
        self.gateway.delete_server.return_value = Ok(True)
        self.registration = Mock()
        self.registration.unregister_node.return_value = Ok(True)
        self.ssh = Mock()
        self.ssh.delete_deployment_key.return_value = Ok(True)
        self.factory_patch = patch(
            "apps.infrastructure.cloud_destroy_service.get_cloud_gateway", return_value=self.gateway
        )
        self.factory_patch.start()
        self.addCleanup(self.factory_patch.stop)
        preview = inspect_destroy(self.deployment, "token")
        self.plan = approve_destroy(
            self.deployment,
            "token",
            self.actor,
            DestroyApproval(self.deployment.hostname, preview.digest, "keep", "Keep existing restore points"),
        )
        self.lease = claim_teardown(
            self.deployment,
            kind="destroy",
            from_states=("completed",),
            credential_fingerprint=provider_token_fingerprint("token"),
        ).unwrap()
        self.deployment.refresh_from_db()

    def teardown(self):
        return NodeTeardown(
            self.deployment,
            self.lease,
            api_token="token",
            ssh_manager=self.ssh,
            registration=self.registration,
            user=self.actor,
        )

    @patch("apps.infrastructure.deployment_service.NodeDeploymentService._delete_owned_dns", return_value=Ok(True))
    @patch("apps.infrastructure.node_teardown.get_cloud_gateway")
    def test_unconfirmed_retention_refuses_before_unregistration_or_dns_withdrawal(self, factory, dns):
        factory.return_value = self.gateway
        self.client.retain_backup.return_value = Err("snapshot conversion pending")
        result = self.teardown().run()
        self.assertTrue(result.is_err())
        self.registration.unregister_node.assert_not_called()
        dns.assert_not_called()
        self.gateway.delete_server.assert_not_called()
        self.ssh.delete_deployment_key.assert_not_called()

    @patch("apps.infrastructure.deployment_service.NodeDeploymentService._delete_owned_dns", return_value=Ok(True))
    @patch("apps.infrastructure.node_teardown.get_cloud_gateway")
    def test_success_retains_snapshot_and_uses_exact_confirmed_resource_cleanup(self, factory, _dns):
        factory.return_value = self.gateway

        def convert(_backup):
            self.resources[-1] = CloudResource("snapshot", "b", source_ids=("vm",), state="available")
            return Ok("b")

        def delete(kind, resource_id):
            self.resources[:] = [row for row in self.resources if (row.kind, row.resource_id) != (kind, resource_id)]
            return Ok(True)

        self.client.retain_backup.side_effect = convert
        self.client.delete_exact.side_effect = delete
        result = self.teardown().run()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual([(row.kind, row.resource_id) for row in self.resources], [("snapshot", "b")])
        self.client.delete_exact.assert_called_once_with("server", "vm")
        self.assertEqual(
            CloudResourceCleanup.objects.get(plan=self.plan, kind="backup", resource_id="b").state, "retained"
        )
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, "destroyed")
