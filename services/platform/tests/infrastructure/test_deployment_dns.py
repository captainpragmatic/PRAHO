"""#347 GAP 3 — DNS wiring into the deploy / teardown pipeline.

Covers: create+persist (structured provenance), partial-outcome non-leak, zone
fail-closed, owner-scoped teardown + orphan marker, all three compensation paths
invoking DNS deletion, and end-to-end fail-closed compensation.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Err, Ok
from apps.infrastructure.cloud_gateway import ServerCreateResult
from apps.infrastructure.deployment_service import NodeDeploymentService
from apps.infrastructure.dns_gateway import DnsRecordResult, ReconcileOutcome
from apps.infrastructure.models import NodeDeploymentLog
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service

_DNS_GW = "apps.infrastructure.deployment_service.get_dns_gateway"
_GET_SETTING = "apps.infrastructure.deployment_service.SettingsService.get_setting"


def _noop_log(level: str, message: str) -> None:
    pass


def _a_result(zone: str = "z1", content: str = "1.2.3.4") -> DnsRecordResult:
    return DnsRecordResult(
        provider="cloudflare",
        zone_id=zone,
        record_id="rA",
        record_type="A",
        name="node",
        content=content,
        owner_tag="t",
    )


def _entry(zone: str = "z1", rid: str = "rA") -> dict[str, str]:
    return {"provider": "cloudflare", "zone_id": zone, "record_id": rid, "type": "A", "name": "n", "owner_tag": "t"}


class ConfigureDnsTests(TestCase):
    """_configure_dns: persistence, partial non-leak, fail-closed on zone problems."""

    def _dep(self):
        dep = _create_deployment("provisioning_node")
        dep.ipv4_address = "1.2.3.4"
        dep.save()
        return dep

    def _gw(self, *, zone: str = "test.example.com", reconcile: ReconcileOutcome | None = None) -> MagicMock:
        gw = MagicMock()
        gw.get_zone_name.return_value = Ok(zone)
        gw.reconcile_records.return_value = reconcile or ReconcileOutcome(applied=[], error=None)
        return gw

    def test_persists_applied_records_as_structured_provenance(self) -> None:
        dep = self._dep()
        gw = self._gw(reconcile=ReconcileOutcome(applied=[_a_result()], error=None))
        with patch(_DNS_GW, return_value=gw):
            res = _make_service()._configure_dns(dep, "tok", "z1", _noop_log)
        self.assertTrue(res.is_ok(), res)
        dep.refresh_from_db()
        self.assertEqual(len(dep.dns_record_ids), 1)
        self.assertEqual(dep.dns_record_ids[0]["type"], "A")
        self.assertEqual(dep.dns_record_ids[0]["zone_id"], "z1")

    def test_partial_failure_persists_applied_then_errs(self) -> None:
        # A applied but AAAA failed → Err returned, yet the A record IS persisted (not leaked).
        dep = self._dep()
        gw = self._gw(reconcile=ReconcileOutcome(applied=[_a_result()], error="AAAA failed"))
        with patch(_DNS_GW, return_value=gw):
            res = _make_service()._configure_dns(dep, "tok", "z1", _noop_log)
        self.assertTrue(res.is_err())
        dep.refresh_from_db()
        self.assertEqual(len(dep.dns_record_ids), 1)

    def test_reconcile_error_leaves_cleanup_provenance(self) -> None:
        # A failed/ambiguous create (applied empty, error set — e.g. the POST reached
        # Cloudflare but the connection dropped) must still leave zone+owner provenance so
        # owner-tag teardown can sweep the possibly-orphaned record (codex P1).
        dep = self._dep()
        gw = self._gw(reconcile=ReconcileOutcome(applied=[], error="connection dropped after POST"))
        with patch(_DNS_GW, return_value=gw):
            res = _make_service()._configure_dns(dep, "tok", "zone-xyz", _noop_log)
        self.assertTrue(res.is_err())
        dep.refresh_from_db()
        self.assertTrue(dep.dns_record_ids, "cleanup provenance must survive a failed reconcile")
        self.assertEqual(dep.dns_record_ids[0]["zone_id"], "zone-xyz")

    def test_zone_mismatch_fails_closed_without_reconciling(self) -> None:
        dep = self._dep()
        gw = self._gw(zone="someone-elses-zone.com")
        with patch(_DNS_GW, return_value=gw):
            res = _make_service()._configure_dns(dep, "tok", "z1", _noop_log)
        self.assertTrue(res.is_err())
        gw.reconcile_records.assert_not_called()

    def test_zone_check_error_fails_closed(self) -> None:
        dep = self._dep()
        gw = MagicMock()
        gw.get_zone_name.return_value = Err("401 unauthorized")
        with patch(_DNS_GW, return_value=gw):
            res = _make_service()._configure_dns(dep, "tok", "z1", _noop_log)
        self.assertTrue(res.is_err())
        gw.reconcile_records.assert_not_called()


class DeleteOwnedDnsTests(TestCase):
    """_delete_owned_dns: owner-scoped delete, clear-on-success, orphan marker on failure."""

    def test_deletes_by_tag_and_clears(self) -> None:
        dep = _create_deployment("completed")
        dep.dns_record_ids = [_entry()]
        dep.save()
        gw = MagicMock()
        gw.delete_owned_records.return_value = Ok(["rA"])
        with patch(_DNS_GW, return_value=gw), patch(_GET_SETTING, return_value="tok"):
            NodeDeploymentService._delete_owned_dns(dep)
        gw.delete_owned_records.assert_called_once_with("z1", NodeDeploymentService._dns_owner_tag(dep))
        dep.refresh_from_db()
        self.assertEqual(dep.dns_record_ids, [])

    def test_delete_failure_writes_orphan_marker_and_retains(self) -> None:
        dep = _create_deployment("completed")
        dep.dns_record_ids = [_entry()]
        dep.save()
        gw = MagicMock()
        gw.delete_owned_records.return_value = Err("cloudflare down")
        with patch(_DNS_GW, return_value=gw), patch(_GET_SETTING, return_value="tok"):
            NodeDeploymentService._delete_owned_dns(dep)
        dep.refresh_from_db()
        self.assertEqual(len(dep.dns_record_ids), 1)  # retained for reconciliation
        self.assertTrue(
            NodeDeploymentLog.objects.filter(deployment=dep, message__icontains="orphan").exists()
        )

    def test_no_entries_is_noop(self) -> None:
        dep = _create_deployment("completed")  # dns_record_ids defaults to []
        gw = MagicMock()
        with patch(_DNS_GW, return_value=gw):
            NodeDeploymentService._delete_owned_dns(dep)
        gw.delete_owned_records.assert_not_called()

    def test_missing_token_writes_skip_marker_without_calling_gateway(self) -> None:
        dep = _create_deployment("completed")
        dep.dns_record_ids = [_entry()]
        dep.save()
        gw = MagicMock()
        with patch(_DNS_GW, return_value=gw), patch(_GET_SETTING, return_value=""):
            NodeDeploymentService._delete_owned_dns(dep)
        gw.delete_owned_records.assert_not_called()
        self.assertTrue(NodeDeploymentLog.objects.filter(deployment=dep, message__icontains="orphaned").exists())


class TeardownPathsInvokeDnsDeletion(TestCase):
    """All THREE compensation paths must call _delete_owned_dns (codex C1)."""

    def test_cleanup_resources_invokes_dns_deletion(self) -> None:
        dep = _create_deployment("provisioning_node")
        svc = _make_service()
        with patch.object(NodeDeploymentService, "_delete_owned_dns") as spy:
            svc._cleanup_resources(MagicMock(), [], dep)
        spy.assert_called_once_with(dep)

    def test_destroy_node_invokes_dns_deletion(self) -> None:
        dep = _create_deployment("completed")  # no virtualmin_server, no external_node_id
        svc = _make_service()
        with patch.object(NodeDeploymentService, "_delete_owned_dns") as spy:
            svc.destroy_node(dep, credentials={"api_token": "x"})
        spy.assert_called_once_with(dep)

    def test_scheduled_teardown_invokes_dns_deletion(self) -> None:
        from apps.infrastructure.tasks import _teardown_cloud_deployment  # noqa: PLC0415

        dep = _create_deployment("failed")
        with patch.object(NodeDeploymentService, "_delete_owned_dns") as spy:
            _teardown_cloud_deployment(dep)
        spy.assert_called_once_with(dep)


class DeployFailClosedOnDnsError(TestCase):
    """A DNS failure mid-deploy fails closed AND compensates the just-provisioned VM."""

    def test_dns_error_marks_failed_and_cleans_up_vm(self) -> None:
        dep = _create_deployment("pending")
        svc = _make_service()
        svc._ssh_manager.generate_deployment_key.return_value = Ok(MagicMock(public_key="ssh-rsa AAAA"))

        cloud = MagicMock()
        cloud.upload_ssh_key.return_value = Ok("praho-key")
        cloud.create_firewall.return_value = Ok("fw-1")
        cloud.create_server.return_value = Ok(
            ServerCreateResult(server_id="srv-1", ipv4_address="1.2.3.4", ipv6_address="")
        )
        cloud.delete_server.return_value = Ok(True)

        dns = MagicMock()
        dns.get_zone_name.return_value = Ok("test.example.com")
        dns.reconcile_records.return_value = ReconcileOutcome(applied=[], error="cloudflare rejected the record")

        with (
            patch(_GET_SETTING, return_value=True),
            patch(_DNS_GW, return_value=dns),
            patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=cloud),
        ):
            result = svc.deploy_node(deployment=dep, credentials={"api_token": "test-token"})

        self.assertTrue(result.is_err())
        dep.refresh_from_db()
        self.assertEqual(dep.status, "failed")
        # Compensated: the VM created before the DNS stage was torn down.
        cloud.delete_server.assert_called_once_with("srv-1")
