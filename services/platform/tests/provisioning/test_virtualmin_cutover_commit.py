"""The ownership transaction precedes every opportunity to write on the target."""

from datetime import timedelta
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Err, Ok, Retriability
from apps.infrastructure.dns_agreement import Agreement
from apps.infrastructure.panel_cert_probes import AuthoritativeAnswer
from apps.provisioning import managed_dns_service as managed
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.account_hostname_service import EnsureOutcome
from apps.provisioning.migration_bridge_service import BridgePreparation
from apps.provisioning.virtualmin_gateway import listing_attribute
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import (
    MigrationDeferredError,
    VirtualminMigrationService,
    resolve_migration,
)
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.test_virtualmin_migration_barrier_wiring import BarrierCase


class CutoverCommitTests(BarrierCase):
    def test_authoritative_generation_still_matches_when_completion_commits(self):
        migration, token = self.committed_bridge()
        bridge = MigrationBridge.objects.get(migration=migration)
        bridge.activate()
        bridge.save()
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="repointing")
        migration.refresh_from_db()
        original = managed.observe_routing

        def observe_then_readdress(hostname):
            result = original(hostname)
            self.assertTrue(result.unwrap()["agreed"])
            VirtualminServer.objects.filter(pk=migration.target_server_id).update(ipv4_address="95.217.0.30")
            return result

        with (
            patch("apps.provisioning.account_hostname_service.sync_account_hostname", return_value=Ok("published")),
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch.object(managed, "observe_routing", side_effect=observe_then_readdress),
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"),
            self.assertRaises(MigrationDeferredError),
        ):
            VirtualminMigrationService()._converge_cutover(migration, token)

    def setUp(self):
        super().setUp()
        self.server.ipv4_address = "95.217.0.10"
        self.server.save(update_fields=["ipv4_address"])
        self.enterContext(
            patch("apps.provisioning.migration_routing.routing_agreement", return_value=Agreement(True, 300))
        )

    def preparation(self):
        return Ok(BridgePreparation("origin-pem", timezone.now() + timedelta(days=30)))

    def restored(self):
        self.target.ipv4_address = "95.217.0.20"
        self.target.save(update_fields=["ipv4_address"])
        migration, token = self._held(
            "verifying", contract="cutover", restore_issued=True, barrier_state={"held_restore_complete": True}
        )
        self.source_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        target = self.target_gateway.seed_domain(
            self.account.domain, username=self.account.virtualmin_username, enabled=False
        )
        target.features = str(
            listing_attribute(migration.pre_migration_snapshot["remote"]["attributes"], "Features")
        ).split()
        name = AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        return migration, token, name

    def test_verified_restore_commits_both_owners_before_enable_and_reserves_the_bridge(self):
        migration, token, name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=True, certificate_installed=True)
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
        ):
            VirtualminMigrationService()._verify(migration, token)

        self.account.refresh_from_db()
        name.refresh_from_db()
        migration.refresh_from_db()
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertEqual(name.target_server_id, self.target.pk)
        self.assertIsNotNone(migration.cutover_committed_at)
        self.assertEqual(migration.status, "activating")
        self.assertEqual(MigrationBridge.objects.get(migration=migration).status, "pending")
        bridge = MigrationBridge.objects.get(migration=migration)
        self.assertIn(self.account.domain, bridge.evidence["dns_names"])
        self.assertIn(name.fqdn, bridge.evidence["frontend_dns_before"])
        self.assertNotIn("enable-domain", self._programs("target"))

    def test_cancellation_arriving_during_bridge_preparation_aborts_before_the_ownership_commit(self):
        migration, token, name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=True, certificate_installed=True)
        service = VirtualminMigrationService()

        def prepare(_migration):
            VirtualminMigration.objects.filter(pk=migration.pk).update(cancel_requested=True)
            self.assertFalse(migration.cancel_requested, "the caller must really hold the stale pre-cancel instance")
            return self.preparation()

        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", side_effect=prepare),
            patch.object(service, "_abort") as abort,
        ):
            service._verify(migration, token)
        abort.assert_called_once()
        self.assertIn("cancel", str(abort.call_args.args[2]).lower())
        self.account.refresh_from_db()
        name.refresh_from_db()
        migration.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(name.target_server_id, self.server.pk)
        self.assertIsNone(migration.cutover_committed_at)
        self.assertFalse(MigrationBridge.objects.filter(migration=migration).exists())
        self.assertNotIn("enable-domain", self._programs("target"))

    def test_missing_target_name_certificate_never_commits_or_enables(self):
        migration, token, name = self.restored()
        with patch(
            "apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Err("no cert")
        ):
            VirtualminMigrationService()._verify(migration, token)

        self.account.refresh_from_db()
        name.refresh_from_db()
        migration.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(name.target_server_id, self.server.pk)
        self.assertIsNone(migration.cutover_committed_at)
        self.assertNotEqual(migration.status, "activating")
        self.assertNotIn("enable-domain", self._programs("target"))

    def test_frontend_old_ttls_must_fit_the_bridge_certificate_lifetime_before_commit(self):
        migration, token, name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=True, certificate_installed=True)
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch(
                "apps.provisioning.migration_bridge_service.prepare_bridge",
                return_value=Ok(
                    BridgePreparation("origin-pem", timezone.now() + timedelta(hours=49), (self.account.domain,))
                ),
            ),
            patch("apps.provisioning.migration_routing.routing_agreement", return_value=Agreement(True, 7200)),
        ):
            VirtualminMigrationService()._verify(migration, token)
        migration.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)
        name.refresh_from_db()
        self.assertEqual(name.target_server_id, self.server.pk)

    def test_unknown_frontend_old_ttl_compensates_before_the_ownership_commit(self):
        migration, token, name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=True, certificate_installed=True)
        service = VirtualminMigrationService()
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
            patch(
                "apps.provisioning.migration_routing.routing_agreement",
                return_value=Agreement(False, detail="DNS query failed"),
            ),
            patch.object(service, "_abort") as abort,
        ):
            service._verify(migration, token)
        abort.assert_called_once()
        self.assertIn("TTL", str(abort.call_args.args[2]))
        migration.refresh_from_db()
        name.refresh_from_db()
        self.account.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(name.target_server_id, self.server.pk)
        self.assertFalse(MigrationBridge.objects.filter(migration=migration).exists())
        self.assertNotIn("enable-domain", self._programs("target"))

    def test_a_name_without_preview_linking_can_commit_while_the_psl_gate_is_closed(self):
        migration, token, _name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True)
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.account_hostname_config.account_zone_psl_shipped", return_value=False),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
        ):
            VirtualminMigrationService()._verify(migration, token)
        migration.refresh_from_db()
        self.assertIsNotNone(migration.cutover_committed_at)

    def test_uncommitted_cutover_cannot_enable_the_target(self):
        migration, token = self._held("activating", contract="cutover")
        self.target_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        with self.assertRaisesRegex(ValueError, "commit"):
            VirtualminMigrationService()._activate(migration, token)
        self.assertNotIn("enable-domain", self._programs("target"))

    def committed_bridge(self):
        migration, token, _name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=True, certificate_installed=True)
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
        ):
            VirtualminMigrationService()._verify(migration, token)
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status="bridging"
        )  # fsm-bypass: committed phase fixture
        migration.refresh_from_db()
        self.target_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=True)
        return migration, token

    def test_transient_bridge_error_replays_forward_to_completion(self):
        migration, token = self.committed_bridge()
        service = VirtualminMigrationService()
        with (
            patch(
                "apps.provisioning.migration_bridge_service.install_bridge",
                side_effect=[Err("timeout", retriability=Retriability.RETRIABLE), Ok("installed")],
            ),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.account_hostname_service.sync_account_hostname", return_value=Ok("published")),
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup") as cleanup,
        ):
            service.execute(migration, token)
            migration.refresh_from_db()
            self.assertEqual(migration.status, "bridging")
            self.assertIsNotNone(migration.resume_after)
            migration.transition(
                token,
                "bridging",
                "bridging",
                lease_token=None,
                worker_lease_expires_at=None,
                resume_after=timezone.now() - timedelta(seconds=1),
            )
            with self.captureOnCommitCallbacks(execute=True):
                result = service.run(migration.pk)
            self.assertTrue(result.is_ok(), result)
            cleanup.assert_called_once_with(migration.pk)
        migration.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(migration.status, "completed")
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertNotIn("enable-domain", self._programs("source"))
        self.assertNotIn("delete-domain", self._programs("target"))

    def test_staff_resolution_of_a_committed_failure_retries_the_target(self):
        migration, token = self.committed_bridge()
        with patch(
            "apps.provisioning.migration_bridge_service.install_bridge",
            return_value=Err("blocked", retriability=Retriability.NOT_RETRIABLE),
        ):
            VirtualminMigrationService().execute(migration, token)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "needs_review")
        self.assertEqual(migration.parked_phase, "bridging")
        migration.transition(token, "needs_review", "needs_review", lease_token=None, worker_lease_expires_at=None)
        with self.captureOnCommitCallbacks(execute=True):
            result = resolve_migration(migration, resolved_by=self.staff, note="bridge access repaired")
        self.assertTrue(result.is_ok(), result)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "bridging")
        self.assertEqual(migration.parked_phase, "")

    def test_a_staff_fenced_failed_source_can_finish_dns_on_the_committed_target_without_source_calls(self):
        migration, token = self.committed_bridge()
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review", parked_phase="bridging")
        migration.refresh_from_db()
        migration.transition(token, "needs_review", "needs_review", lease_token=None, worker_lease_expires_at=None)
        with patch.object(VirtualminMigrationService, "_enqueue"):
            resolved = resolve_migration(
                migration,
                resolved_by=self.staff,
                note="Continue target after source failure",
                source_fenced="Provider confirms the old instance is powered off and isolated",
            )
        self.assertTrue(resolved.is_ok(), resolved)
        migration.refresh_from_db()
        bridge = MigrationBridge.objects.get(migration=migration)
        self.assertEqual(bridge.status, "failed", "an unreachable source must never be represented as a live bridge")
        self.assertEqual(migration.barrier_state["source_fenced_control"]["source_server_id"], str(self.server.pk))
        audit = AuditEvent.objects.filter(action="virtualmin_migration_keep_target").latest("timestamp")
        self.assertEqual(audit.metadata["source_fenced_control"], migration.barrier_state["source_fenced_control"])
        self.events.clear()
        service = VirtualminMigrationService()
        domain = service._domain

        def target_only(server, name):
            self.assertEqual(
                server.pk, self.target.pk, "a fenced failed source must never be called for forward convergence"
            )
            return domain(server, name)

        with (
            patch.object(service, "_domain", side_effect=target_only),
            patch(
                "apps.provisioning.migration_bridge_service.install_bridge",
                side_effect=AssertionError("source bridge RPC"),
            ),
            patch(
                "apps.provisioning.migration_bridge_service.verify_bridge",
                side_effect=AssertionError("source bridge RPC"),
            ),
            patch("apps.provisioning.account_hostname_service.sync_account_hostname", return_value=Ok("published")),
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"),
        ):
            result = service.run(migration.pk)
        self.assertTrue(result.is_ok(), result)
        migration.refresh_from_db()
        self.account.refresh_from_db()
        bridge.refresh_from_db()
        self.assertEqual(migration.status, "completed")
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertEqual(bridge.status, "failed")
        self.assertEqual(self._programs("source"), [])
        self.assertNotIn("delete-domain", self._programs("target"))

    def test_source_fencing_cannot_bypass_the_point_of_no_return(self):
        migration, token, _name = self.restored()
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review")
        migration.refresh_from_db()
        migration.transition(token, "needs_review", "needs_review", lease_token=None, worker_lease_expires_at=None)
        result = resolve_migration(migration, resolved_by=self.staff, note="", source_fenced="powered off")
        self.assertTrue(result.is_err())
        migration.refresh_from_db()
        self.assertEqual(migration.status, "needs_review")
        self.assertNotIn("source_fenced_control", migration.barrier_state)

    def test_staff_resolution_form_records_the_explicit_source_fencing_control(self):
        migration, token = self.committed_bridge()
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review", parked_phase="bridging")
        migration.refresh_from_db()
        migration.transition(token, "needs_review", "needs_review", lease_token=None, worker_lease_expires_at=None)
        self.client.force_login(self.staff)
        with patch.object(VirtualminMigrationService, "_enqueue"), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("provisioning:virtualmin_migration_resolve", args=[self.account.pk]),
                {"migration_id": str(migration.pk), "source_fenced": "Provider instance is off", "note": "Keep target"},
            )
        self.assertEqual(response.status_code, 302)
        migration.refresh_from_db()
        self.assertEqual(migration.barrier_state["source_fenced_control"]["attestation"], "Provider instance is off")

    def test_nonstaff_cannot_attest_a_failed_source_even_through_the_service_api(self):
        migration, token = self.committed_bridge()
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review", parked_phase="bridging")
        migration.refresh_from_db()
        migration.transition(token, "needs_review", "needs_review", lease_token=None, worker_lease_expires_at=None)
        self.staff.staff_role = ""
        self.staff.is_staff = False
        self.staff.is_superuser = False
        result = resolve_migration(migration, resolved_by=self.staff, note="", source_fenced="Powered off")
        self.assertTrue(result.is_err())
        migration.refresh_from_db()
        self.assertNotIn("source_fenced_control", migration.barrier_state)

    def test_partial_authoritative_convergence_is_recorded_for_each_address_family(self):
        migration, token = self.committed_bridge()
        bridge = MigrationBridge.objects.get(migration=migration)
        bridge.activate()
        bridge.save()
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="repointing")  # fsm-bypass: DNS phase fixture
        migration.refresh_from_db()
        partial = Agreement(
            False,
            detail="AAAA pending",
            answers=(
                AuthoritativeAnswer("ns1.example.net", "A", ("95.217.0.20",)),
                AuthoritativeAnswer("ns1.example.net", "AAAA", ("2a01:4f8::1",)),
            ),
        )
        with (
            patch("apps.provisioning.account_hostname_service.sync_account_hostname", return_value=Ok("published")),
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=partial),
            self.assertRaises(MigrationDeferredError),
        ):
            VirtualminMigrationService()._converge_cutover(migration, token)
        migration.refresh_from_db()
        progress = migration.barrier_state["dns"]["records"]
        self.assertTrue(progress["A"]["agreed"])
        self.assertFalse(progress["AAAA"]["agreed"])
