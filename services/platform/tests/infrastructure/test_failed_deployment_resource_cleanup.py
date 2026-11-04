"""A failed provisioning attempt cannot bypass provider inventory or backup retention consent."""

from unittest.mock import Mock, patch

from django.test import TestCase
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.cloud_destroy_models import CloudResourceRetention
from apps.infrastructure.cloud_destroy_service import record_resource_ownership
from apps.infrastructure.cloud_resource_inventory import CAPABILITIES, CloudResource
from apps.infrastructure.deployment_lifecycle import claim_operation, provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeServerLifetime
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service


class FailedDeploymentResourceCleanupTests(TestCase):
    def setUp(self):
        self.deployment = _create_deployment("pending", external_node_id="vm")
        self.deployment.provider_token_fingerprint = provider_token_fingerprint("token")
        self.deployment.server_create_state = "created"
        self.deployment.save(update_fields=["provider_token_fingerprint", "server_create_state"])
        self.lease = claim_operation(
            self.deployment.pk, from_states=("pending",), to_status="provisioning_node", kind="deploy"
        ).unwrap()
        self.deployment.refresh_from_db()
        self.resources = [CloudResource("server", "vm")]
        self.events = []
        self.client = Mock(capabilities=CAPABILITIES["hetzner"])
        self.client.inventory.side_effect = lambda _ids: Ok(list(self.resources))
        self.client.read_exact.side_effect = self.read
        self.client.delete_exact.side_effect = self.delete
        self.client.confirm_absent.side_effect = lambda kind, identifier: (
            Err("resource still present")
            if any(row.kind == kind and row.resource_id == identifier for row in self.resources)
            else Ok(True)
        )
        self.gateway = Mock()
        self.gateway.resource_client.return_value = self.client
        self.service = _make_service()

    def read(self, kind, identifier):
        self.events.append(("read", kind, identifier))
        row = next((row for row in self.resources if (row.kind, row.resource_id) == (kind, identifier)), None)
        return {"id": identifier, "type": kind, "status": "available"} if row else None

    def delete(self, kind, identifier):
        self.events.append(("delete", kind, identifier))
        self.resources[:] = [row for row in self.resources if (row.kind, row.resource_id) != (kind, identifier)]
        return Ok(True)

    def cleanup(self):
        return self.service._cleanup_resources(
            self.gateway, [("server", "vm")], self.deployment, lease=self.lease, api_token="token"
        )

    def test_existing_backups_refuse_before_dns_or_credential_withdrawal(self):
        self.resources.append(CloudResource("backup", "backup", source_ids=("vm",), state="available"))
        with (
            patch.object(self.service, "_delete_owned_dns") as dns,
            patch("apps.infrastructure.deployment_service.deactivate_api_credential") as api,
        ):
            self.cleanup()
        dns.assert_not_called()
        api.assert_not_called()
        self.client.delete_exact.assert_not_called()
        self.gateway.delete_server.assert_not_called()
        self.assertEqual(self.deployment.destroy_plans.get().restore_point_policy, "preserve")

    def test_keeps_verified_snapshots_and_cleans_exact_owned_dependencies(self):
        self.resources.extend(
            [
                CloudResource("snapshot", "snapshot", source_ids=("vm",), state="available"),
                CloudResource("primary_ip", "ip", attached_to=("vm",)),
            ]
        )
        record_resource_ownership(self.deployment, "primary_ip", "ip", "create_response")

        def dns(*_args):
            self.events.append(("dns",))
            return Ok(True)

        with (
            patch.object(self.service, "_delete_owned_dns", side_effect=dns),
            patch("apps.infrastructure.deployment_service.deactivate_api_credential") as api,
        ):
            self.cleanup()
        self.assertEqual([(row.kind, row.resource_id) for row in self.resources], [("snapshot", "snapshot")])
        self.assertLess(self.events.index(("read", "snapshot", "snapshot")), self.events.index(("dns",)))
        self.assertTrue(CloudResourceRetention.objects.filter(resource_id="snapshot").exists())
        api.assert_called_once_with(self.deployment)
        self.gateway.delete_server.assert_not_called()
        self.deployment.refresh_from_db()
        self.assertEqual(
            (self.deployment.status, self.deployment.operation_token), ("provisioning_node", self.lease.token)
        )

    def test_incomplete_inventory_and_lost_lease_have_no_external_side_effect(self):
        self.client.inventory.return_value = Err("permission denied")
        self.client.inventory.side_effect = None
        with patch.object(self.service, "_delete_owned_dns") as dns:
            self.cleanup()
            NodeDeployment.objects.filter(pk=self.deployment.pk).update(operation_token=None)
            self.cleanup()
        dns.assert_not_called()
        self.client.delete_exact.assert_not_called()

    def test_confirmed_vm_absence_ends_billing_when_a_dependency_remains(self):
        self.resources.append(CloudResource("firewall", "firewall", attached_to=("vm",)))
        record_resource_ownership(self.deployment, "firewall", "firewall", "create_response")
        NodeServerLifetime.objects.create(
            deployment=self.deployment,
            correlation_id=self.deployment.correlation_id,
            server_id="vm",
            node_size=self.deployment.node_size,
            monthly_cost_eur=3,
            started_at=timezone.now(),
        )
        original = self.delete
        self.client.delete_exact.side_effect = lambda kind, rid: (
            Err("denied") if kind == "firewall" else original(kind, rid)
        )
        with patch.object(self.service, "_delete_owned_dns", return_value=Ok(True)):
            self.cleanup()
        self.assertEqual([(row.kind, row.resource_id) for row in self.resources], [("firewall", "firewall")])
        self.assertFalse(self.deployment.server_lifetimes.filter(ended_at__isnull=True).exists())
