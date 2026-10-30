"""The shared teardown proves each resource gone or stops with the row still destroying, then resumes.

Each boundary (unregister, DNS, server, firewall, SSH key, vault) is failed once: the row stays
``destroying`` with every identifier not yet proven gone, and a second run finishes without repeating
the destructive calls that already succeeded. DNS is withdrawn before any server is deleted.
"""

from __future__ import annotations

import itertools
from typing import Any
from unittest import mock

from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.audit_service import InfrastructureAuditContext
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service
from tests.infrastructure.test_node_admission_guard import make_service as make_hosting_service

TOKEN = "teardown-token"
_NODE_NUMBERS = itertools.count(1)


def cloud_gateway() -> mock.Mock:
    gateway = mock.Mock()
    gateway.find_servers_by_label.return_value = Ok([])
    gateway.get_server.return_value = Ok(mock.Mock(server_id="srv-1"))
    gateway.delete_server.return_value = Ok(True)
    gateway.find_firewalls_by_label.return_value = Ok(["fw-1"])
    gateway.delete_firewall.return_value = Ok(True)
    gateway.find_ssh_keys_by_label.return_value = Ok(["7"])
    gateway.delete_ssh_key_by_id.return_value = Ok(True)
    return gateway


def dns_gateway() -> mock.Mock:
    gateway = mock.Mock()
    gateway.delete_owned_records.return_value = Ok(["rA"])
    gateway.confirm_no_owned_records.return_value = Ok(True)
    return gateway


class Harness:
    """A registered, DNS-published, billed node and the collaborators the teardown calls."""

    def __init__(self, *, fingerprint: str = provider_token_fingerprint(TOKEN)) -> None:
        name = f"td-node-{next(_NODE_NUMBERS)}"
        self.server = VirtualminServer.objects.create(
            name=name, hostname=f"{name}.example.test", api_username="api", encrypted_api_password=b""
        )
        deployment = _create_deployment("completed", external_node_id="srv-1")
        tag = f"praho:node-deploy:{deployment.correlation_id}"
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            virtualmin_server=self.server,
            server_create_state="created",
            provider_token_fingerprint=fingerprint,
            dns_record_ids=[{"zone_id": "z1", "record_id": "rA", "type": "A", "name": "n", "owner_tag": tag}],
        )
        self.deployment = NodeDeployment.objects.get(pk=deployment.pk)
        self.service = _make_service()
        self.service._registration.unregister_node.side_effect = self._unregister
        self.cloud = cloud_gateway()
        self.dns = dns_gateway()

    def _unregister(self, deployment: NodeDeployment, **_kwargs: Any) -> Ok[bool]:
        NodeDeployment.objects.filter(pk=deployment.pk).update(virtualmin_server=None)
        deployment.virtualmin_server = None
        return Ok(True)

    def _patches(self) -> Any:
        return (
            mock.patch("apps.infrastructure.node_teardown.get_cloud_gateway", return_value=self.cloud),
            mock.patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=self.dns),
            mock.patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value="dns-tok"),
        )

    def destroy(self) -> Any:
        cloud, dns, setting = self._patches()
        with cloud, dns, setting:
            return self.service.destroy_node(self.deployment, credentials={"api_token": TOKEN})

    def resume(self) -> Any:
        from apps.infrastructure.node_teardown import claim_teardown, run_claimed_teardown  # noqa: PLC0415

        lease = claim_teardown(self.deployment, kind="teardown", from_states=("destroying",)).unwrap()
        self.deployment.refresh_from_db()
        cloud, dns, setting = self._patches()
        with cloud, dns, setting:
            return run_claimed_teardown(
                self.deployment,
                lease,
                TOKEN,
                ssh_manager=self.service._ssh_manager,
                registration=self.service._registration,
                audit_ctx=InfrastructureAuditContext(),
            )

    def row(self) -> NodeDeployment:
        return NodeDeployment.objects.get(pk=self.deployment.pk)


class InterruptionAndResumeTests(TestCase):
    def _fail_then_resume(self, inject: str) -> Harness:
        h = Harness()
        def fail_unregister() -> None:
            h.service._registration.unregister_node.side_effect = None
            h.service._registration.unregister_node.return_value = Err("panel down")

        failures = {
            "unregister": fail_unregister,
            "dns": lambda: h.dns.confirm_no_owned_records.configure_mock(return_value=Ok(False)),
            "server": lambda: h.cloud.delete_server.configure_mock(return_value=Err("still exists")),
            "firewall": lambda: h.cloud.delete_firewall.configure_mock(return_value=Err("in use")),
            "ssh_key": lambda: h.cloud.delete_ssh_key_by_id.configure_mock(return_value=Err("api error")),
            "vault": lambda: h.service._ssh_manager.delete_deployment_key.configure_mock(
                return_value=Err("vault down")
            ),
        }
        failures[inject]()
        self.assertTrue(h.destroy().is_err())
        row = h.row()
        self.assertEqual(row.status, "destroying", inject)
        return h

    def test_unregister_failure_keeps_everything(self) -> None:
        h = self._fail_then_resume("unregister")
        row = h.row()
        self.assertEqual((row.external_node_id, len(row.dns_record_ids)), ("srv-1", 1))
        h.dns.delete_owned_records.assert_not_called()
        h.cloud.delete_server.assert_not_called()

    def test_unconfirmed_dns_stops_before_any_server_delete(self) -> None:
        h = self._fail_then_resume("dns")
        row = h.row()
        self.assertEqual((row.external_node_id, len(row.dns_record_ids)), ("srv-1", 1))
        h.cloud.delete_server.assert_not_called()

    def test_unconfirmed_server_delete_keeps_the_server_id(self) -> None:
        h = self._fail_then_resume("server")
        row = h.row()
        self.assertEqual((row.external_node_id, row.dns_record_ids), ("srv-1", []))
        h.cloud.delete_firewall.assert_not_called()

    def test_each_failure_resumes_to_destroyed_without_repeating_finished_steps(self) -> None:
        for inject in ("unregister", "dns", "server", "firewall", "ssh_key", "vault"):
            with self.subTest(inject=inject):
                h = self._fail_then_resume(inject)
                unregistered = h.service._registration.unregister_node.call_count
                dns_deletes = h.dns.delete_owned_records.call_count
                h.service._registration.unregister_node.side_effect = h._unregister
                for collaborator in (h.dns.confirm_no_owned_records, h.cloud.delete_server, h.cloud.delete_firewall):
                    collaborator.return_value = Ok(True)
                h.cloud.delete_ssh_key_by_id.return_value = Ok(True)
                h.service._ssh_manager.delete_deployment_key.return_value = Ok(True)
                if inject not in ("unregister", "dns", "server"):
                    h.cloud.find_servers_by_label.return_value = Ok([])

                self.assertTrue(h.resume().is_ok(), inject)

                row = h.row()
                self.assertEqual((row.status, row.external_node_id, row.dns_record_ids), ("destroyed", "", []))
                self.assertIsNone(row.operation_token)
                if inject != "unregister":
                    self.assertEqual(h.service._registration.unregister_node.call_count, unregistered)
                if inject not in ("unregister", "dns"):
                    self.assertEqual(h.dns.delete_owned_records.call_count, dns_deletes)
                if inject in ("firewall", "ssh_key", "vault"):
                    self.assertEqual(h.cloud.delete_server.call_count, 1)


class GuardRefusalChangesNothingTests(TestCase):
    def test_an_occupied_node_is_refused_with_nothing_changed(self) -> None:
        h = Harness()
        VirtualminAccount.objects.create(
            domain="live.example.com",
            service=make_hosting_service("live.example.com"),
            server=h.server,
            virtualmin_username="live",
            status="active",
        )

        result = h.destroy()

        self.assertTrue(result.is_err())
        row = h.row()
        self.assertEqual((row.status, row.operation_token, row.external_node_id), ("completed", None, "srv-1"))
        self.assertEqual(VirtualminServer.objects.get(pk=h.server.pk).status, "active")
        h.cloud.delete_server.assert_not_called()
        self.assertTrue(
            NodeDeploymentLog.objects.filter(deployment=row, level="ERROR", message__startswith="Destroy refused").exists()
        )


class ProvenanceTests(TestCase):
    def test_a_different_token_keeps_identifiers_and_asks_for_reconciliation(self) -> None:
        h = Harness(fingerprint=provider_token_fingerprint("another-token"))

        self.assertTrue(h.destroy().is_err())

        row = h.row()
        self.assertEqual((row.status, row.external_node_id, row.needs_reconciliation), ("destroying", "srv-1", True))
        h.cloud.delete_server.assert_not_called()

    def test_unknown_provenance_never_trusts_not_found(self) -> None:
        h = Harness(fingerprint="")
        h.cloud.get_server.return_value = Ok(None)

        self.assertTrue(h.destroy().is_err())

        row = h.row()
        self.assertEqual((row.external_node_id, row.needs_reconciliation), ("srv-1", True))
        h.cloud.delete_server.assert_not_called()

    def test_unknown_provenance_deletes_a_server_this_token_can_see(self) -> None:
        h = Harness(fingerprint="")

        self.assertTrue(h.destroy().is_ok())
        h.cloud.delete_server.assert_called_once_with("srv-1")

    def test_a_row_that_never_reached_the_provider_needs_no_token_or_provider(self) -> None:
        deployment = _create_deployment("failed")
        service = _make_service()
        with mock.patch("apps.infrastructure.node_teardown.get_cloud_gateway") as get_gateway:
            result = service.destroy_node(deployment, credentials={})

        self.assertTrue(result.is_ok(), result)
        get_gateway.assert_not_called()
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroyed")


class DrainedNodeTests(TestCase):
    def test_a_server_kept_by_its_drain_history_is_unregistered_not_deleted(self) -> None:
        from apps.infrastructure.registration_service import get_registration_service  # noqa: PLC0415
        from apps.provisioning.virtualmin_migration_models import NodeDrain  # noqa: PLC0415

        h = Harness()
        NodeDrain.objects.create(server=h.server, status="completed")

        result = get_registration_service().unregister_node(h.deployment, delete_server=True)

        self.assertTrue(result.is_ok(), result)
        h.deployment.refresh_from_db()
        self.assertIsNone(h.deployment.virtualmin_server_id)
        self.assertEqual(VirtualminServer.objects.get(pk=h.server.pk).status, "disabled")


class AmbiguousProviderWritesTests(TestCase):
    def test_a_key_or_firewall_created_without_a_server_is_still_discovered(self) -> None:
        deployment = _create_deployment("failed")
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            server_create_state="none", provider_token_fingerprint=provider_token_fingerprint(TOKEN)
        )
        deployment.refresh_from_db()
        cloud = cloud_gateway()
        service = _make_service()

        with mock.patch("apps.infrastructure.node_teardown.get_cloud_gateway", return_value=cloud):
            result = service.destroy_node(deployment, credentials={"api_token": TOKEN})

        self.assertTrue(result.is_ok(), result)
        cloud.delete_firewall.assert_called_once_with("fw-1")
        cloud.delete_ssh_key_by_id.assert_called_once_with("7")
