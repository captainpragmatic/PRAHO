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
from apps.provisioning.migration_barrier import BarrierRecord, BarrierStep
from apps.provisioning.migration_bridge_service import BridgePreparation
from apps.provisioning.virtualmin_gateway import listing_attribute
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import (
    MigrationDeferredError,
    VirtualminMigrationService,
    resolve_migration,
)
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.test_virtualmin_migration_barrier_wiring import RECORD, TOKEN, BarrierCase

KILLED_AT = 1_700_000_000


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

    def test_source_neutral_policy_precedes_ttl_lowering_even_for_an_unpublished_name(self):
        migration, token = self._held("lowering_ttl", contract="cutover")
        AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        steps = []
        with (
            patch(
                "apps.provisioning.account_hostname_service.prepare_account_name_neutral",
                side_effect=lambda *args, **kwargs: steps.append("neutral") or Ok("a" * 64),
            ) as guard,
            patch(
                "apps.provisioning.account_hostname_service.lower_account_hostname_ttl",
                side_effect=lambda *args: steps.append("ttl") or Ok("skipped:not_published"),
            ),
        ):
            VirtualminMigrationService()._lower_ttl(migration, token)
        self.assertEqual(steps, ["neutral", "ttl"])
        self.assertEqual(guard.call_args.args[0].pk, migration.source_server_id)

    def test_source_neutral_refusal_prevents_ttl_writes_and_cutover_progress(self):
        migration, token = self._held("lowering_ttl", contract="cutover")
        AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        with (
            patch(
                "apps.provisioning.account_hostname_service.prepare_account_name_neutral",
                return_value=Err("unproved neutral source"),
            ),
            patch(
                "apps.provisioning.account_hostname_service.lower_account_hostname_ttl",
                return_value=Ok("skipped:not_published"),
            ) as lower,
        ):
            VirtualminMigrationService()._lower_ttl(migration, token)
        lower.assert_not_called()
        migration.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)
        self.assertNotIn(migration.status, {"quiescing", "backing_up"})

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
        # Quiesce persisted the record, token and kill time before the backup; a cutover always has them here.
        migration, token = self._held(
            "verifying",
            contract="cutover",
            restore_issued=True,
            barrier_state={"held_restore_complete": True, "record": RECORD, "token": TOKEN, "killed_at": KILLED_AT},
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
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
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

    def barrier_calls(self, verify):
        """Barrier runs, recorded in the event timeline; `verify` answers the source's re-verification."""
        calls = []

        def run(server, variables):
            action = variables["barrier_action"]
            calls.append((server.pk, action, variables))
            self.events.append(("node", f"barrier:{action}", variables, None))
            if action == "verify":
                held = VirtualminMigration.objects.get(account=self.account)
                self.assertIsNone(held.cutover_committed_at, "the fence is re-verified before the commit")
                self.assertFalse(MigrationBridge.objects.filter(migration=held).exists())
                return verify
            return Ok(BarrierStep("ok", "released" if action == "release" else "idle"))

        return calls, run

    def assert_precommit_abort(self, verify, reason):
        migration, token, name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        calls, run = self.barrier_calls(verify)
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
            patch("apps.provisioning.migration_bridge_service.remove_bridge", return_value=Ok("removed")) as remove,
            patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run),
        ):
            VirtualminMigrationService()._verify(migration, token)
        migration.refresh_from_db()
        self.account.refresh_from_db()
        name.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(name.target_server_id, self.server.pk)
        self.assertFalse(MigrationBridge.objects.filter(migration=migration).exists())
        self.assertEqual(migration.status, "rolled_back")
        self.assertIn(reason, migration.error_detail)
        # Compensation: the target copy and prepared bridge go, then the recorded fence is released.
        self.assertEqual([action for server, action, _ in calls if server == self.server.pk], ["verify", "release"])
        self.assertIsNone(self.target_gateway.domain_state_of(self.account.domain))
        remove.assert_called_once()
        self.assertNotIn("enable-domain", self._programs("target"))

    def test_a_fence_broken_after_the_backup_aborts_before_the_ownership_commit(self):
        self.assert_precommit_abort(
            Ok(BarrierStep("failed", "lock_state_differs:customer@localhost")), "lock_state_differs"
        )

    def test_an_unusable_reverification_aborts_before_the_ownership_commit(self):
        self.assert_precommit_abort(
            Err("Barrier playbook failed or timed out (rc=2)", retriability=Retriability.UNKNOWN), "rc=2"
        )

    def test_a_cutover_without_its_barrier_record_is_refused_before_the_ownership_commit(self):
        migration, token, name = self.restored()
        state = {key: value for key, value in migration.barrier_state.items() if key != "record"}
        VirtualminMigration.objects.filter(pk=migration.pk).update(barrier_state=state)
        migration.refresh_from_db()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        calls, run = self.barrier_calls(Ok(BarrierStep("ok", "holds")))
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
            patch("apps.provisioning.migration_bridge_service.remove_bridge", return_value=Ok("removed")),
            patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run),
            self.assertRaisesRegex(ValueError, "barrier record"),
        ):
            VirtualminMigrationService()._verify(migration, token)
        migration.refresh_from_db()
        self.account.refresh_from_db()
        name.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(name.target_server_id, self.server.pk)
        self.assertEqual(calls, [])

    def test_a_busy_source_defers_the_commit_without_compensating(self):
        migration, token, name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        calls, run = self.barrier_calls(Ok(BarrierStep("busy", "lock_busy")))
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
            patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run),
            patch("apps.provisioning.virtualmin_tasks.schedule_migration_wake") as wake,
        ):
            VirtualminMigrationService().execute(migration, token)
        migration.refresh_from_db()
        self.account.refresh_from_db()
        name.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)
        self.assertEqual((migration.status, migration.parked_phase), ("verifying", ""))
        self.assertIsNotNone(migration.resume_after)
        wake.assert_called_once()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(name.target_server_id, self.server.pk)
        self.assertEqual([action for _, action, _ in calls], ["verify"])
        self.assertIsNotNone(self.target_gateway.domain_state_of(self.account.domain))

    def test_a_holding_fence_is_reverified_with_the_recorded_barrier_and_then_commits(self):
        migration, token, _name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        calls, run = self.barrier_calls(Ok(BarrierStep("ok", "holds")))
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
            patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run),
        ):
            VirtualminMigrationService()._verify(migration, token)
        migration.refresh_from_db()
        self.assertIsNotNone(migration.cutover_committed_at)
        self.assertEqual(migration.status, "activating")
        self.assertEqual([(server, action) for server, action, _ in calls], [(self.server.pk, "verify")])
        variables = calls[0][2]
        record = BarrierRecord.from_state(RECORD).unwrap()
        self.assertNotEqual(variables["barrier_token"], TOKEN, "a fresh token binds the result to this run")
        self.assertEqual(variables["barrier_saved_token"], TOKEN)
        self.assertEqual(variables["barrier_previous_token"], "")
        self.assertEqual(variables["barrier_killed_at"], str(KILLED_AT))
        self.assertEqual(variables["barrier_accounts"], record.accounts_lines())
        self.assertEqual(variables["barrier_enabled"], record.enabled_lines())
        self.assertEqual(
            variables["barrier_domain_id"],
            listing_attribute(migration.pre_migration_snapshot["remote"]["attributes"], "ID"),
        )

    def test_the_fence_is_reverified_after_the_transfer_and_before_the_ownership_commit(self):
        self.target.ipv4_address = "95.217.0.20"
        self.target.save(update_fields=["ipv4_address"])
        migration, token = self._held(
            "backing_up",
            contract="cutover",
            barrier_state={"record": RECORD, "token": TOKEN, "killed_at": KILLED_AT},
        )
        self.source_gateway.domain_state_of(self.account.domain).enabled = False
        AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        features = str(listing_attribute(migration.pre_migration_snapshot["remote"]["attributes"], "Features"))

        def restore(service, held, held_token, _archives):
            target = self.target_gateway.seed_domain(
                self.account.domain, username=self.account.virtualmin_username, enabled=False
            )
            target.features = features.split()
            service._store_barrier_state(held, held_token, {**held.barrier_state, "held_restore_complete": True})
            service._move(held, held_token, "verifying", restore_issued=True)

        transport = self.ansible.return_value.run_playbook.side_effect

        def playbook(deployment, name, *args, **kwargs):
            self.events.append(("node", name, {}, None))
            return transport(deployment, name, *args, **kwargs)

        transition = VirtualminMigration.transition

        def record_commit(instance, held_token, before, after, **fields):
            changed = transition(instance, held_token, before, after, **fields)
            if changed and fields.get("cutover_committed_at") is not None:
                self.events.append(("db", "commit", {}, None))
            return changed

        self.ansible.return_value.run_playbook.side_effect = playbook
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        _calls, run = self.barrier_calls(Ok(BarrierStep("ok", "holds")))
        service = VirtualminMigrationService()
        with (
            patch("apps.provisioning.migration_target_hold.restore_held_target", side_effect=restore),
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
            patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run),
            patch("apps.provisioning.virtualmin_tasks.schedule_migration_wake"),
            patch.object(VirtualminMigration, "transition", new=record_commit),
        ):
            for _checkpoint in range(6):
                service.execute(migration, token)
                migration.refresh_from_db()
                if migration.cutover_committed_at is not None or migration.parked_phase:
                    break
        self.assertEqual(migration.status, "activating")
        milestones = {
            "backup-domain",
            "virtualmin_migrate_fetch.yml",
            "virtualmin_migrate_push.yml",
            "barrier:verify",
            "commit",
        }
        self.assertEqual(
            [program for _, program, _, _ in self.events if program in milestones],
            [
                "backup-domain",
                "virtualmin_migrate_fetch.yml",
                "virtualmin_migrate_push.yml",
                "barrier:verify",
                "commit",
            ],
        )

    def test_cancellation_arriving_during_bridge_preparation_aborts_before_the_ownership_commit(self):
        migration, token, name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
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
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
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
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
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
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.account_hostname_config.account_zone_psl_shipped", return_value=False),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
        ):
            VirtualminMigrationService()._verify(migration, token)
        migration.refresh_from_db()
        self.assertIsNotNone(migration.cutover_committed_at)

    def test_a_neutral_name_can_commit_after_psl_ships_without_enabling_previews(self):
        migration, token, _name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.account_hostname_config.account_zone_psl_shipped", return_value=True),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
        ):
            VirtualminMigrationService()._verify(migration, token)
        migration.refresh_from_db()
        self.assertIsNotNone(migration.cutover_committed_at)

    def test_a_certified_name_without_neutral_proof_cannot_commit(self):
        migration, token, _name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=False)
        with (
            patch("apps.provisioning.virtualmin_migration_service.ensure_on_recreated_node", return_value=Ok(ready)),
            patch("apps.provisioning.account_hostname_config.account_zone_psl_shipped", return_value=False),
            patch("apps.provisioning.migration_bridge_service.prepare_bridge", return_value=self.preparation()),
        ):
            VirtualminMigrationService()._verify(migration, token)
        migration.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)

    def test_uncommitted_cutover_cannot_enable_the_target(self):
        migration, token = self._held("activating", contract="cutover")
        self.target_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        with self.assertRaisesRegex(ValueError, "commit"):
            VirtualminMigrationService()._activate(migration, token)
        self.assertNotIn("enable-domain", self._programs("target"))

    def committed_bridge(self):
        migration, token, _name = self.restored()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
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
