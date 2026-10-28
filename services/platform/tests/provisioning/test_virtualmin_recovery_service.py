"""Recovery selects exact archive lineage and never reaches the unavailable source."""

from copy import deepcopy
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.account_hostname_service import EnsureOutcome
from apps.provisioning.migration_barrier import BarrierStep
from apps.provisioning.virtualmin_backup_service import MANIFEST_VERSION, VirtualminBackupService
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import MigrationDeferredError, resolve_migration
from apps.provisioning.virtualmin_pair_restore import PairStepResult
from apps.provisioning.virtualmin_recovery_service import VirtualminRecoveryService, select_recovery_backups
from tests.provisioning.test_virtualmin_migration_barrier_wiring import BarrierCase

# The node playbook pins Virtualmin's default features; PRAHO nodes host no mail.
NODE_FEATURES = ["unix", "dir", "web", "ssl", "logrotate", "mysql", "webmin"]


def seed_restored(gateway, account, *, enabled):
    """The restored target as a PRAHO node lists it (the mock's own default includes mail)."""
    domain = gateway.seed_domain(account.domain, username=account.virtualmin_username, enabled=enabled)
    domain.features = list(NODE_FEATURES)
    return domain


def manifest(account, backup_id="b" * 32, role="standalone"):
    return {
        "backup_id": backup_id,
        "praho_service_id": str(account.service_id),
        "domain": account.domain,
        "status": "completed",
        "chain_role": role,
        "manifest_version": MANIFEST_VERSION,
        "created_at": "2026-10-27T00:00:00+00:00",
        "include_email": True,
        "include_databases": True,
        "include_files": True,
        "include_ssl": True,
        "virtualmin_domain_id": "17919754553303",
        "node_id": "node-a",
        "chain_epoch": "epoch-1",
        "fp_after": "fingerprint-1",
    }


class RecoveryGuardRetirementTests(BarrierCase):
    def test_abandonment_keeps_exclusion_when_absent_targets_private_tls_is_unproved(self):
        migration, token = self._held("needs_review", contract="recovery")
        self.events.clear()
        with (
            patch("apps.provisioning.virtualmin_recovery_service.run_barrier", return_value=Ok(BarrierStep("ok", "idle"))),
            patch(
                "apps.provisioning.account_hostname_service.retire_removed_node_name",
                return_value=Err("private TLS cleanup unproved"),
            ) as retire,
            patch.object(VirtualminRecoveryService, "_prepare_completion") as complete,
        ):
            result = VirtualminRecoveryService().abandon_precommit(migration, token, actor=self.staff, note="Abandon")
        self.assertTrue(result.is_err())
        retire.assert_called_once()
        complete.assert_not_called()
        migration.refresh_from_db()
        self.assertEqual(migration.status, "needs_review")
        self.assertEqual(self._programs("source"), [])

    def test_abandonment_retires_only_target_guard_before_terminal_completion(self):
        migration, token = self._held("needs_review", contract="recovery")
        self.events.clear()
        steps = []
        with (
            patch("apps.provisioning.virtualmin_recovery_service.run_barrier", return_value=Ok(BarrierStep("ok", "idle"))),
            patch(
                "apps.provisioning.account_hostname_service.retire_removed_node_name",
                side_effect=lambda *args: steps.append("retire") or Ok(None),
            ) as retire,
            patch.object(
                VirtualminRecoveryService, "_prepare_completion", side_effect=lambda *args: steps.append("complete")
            ),
        ):
            result = VirtualminRecoveryService().abandon_precommit(migration, token, actor=self.staff, note="Abandon")
        self.assertTrue(result.is_ok())
        self.assertEqual(steps, ["retire", "complete"])
        self.assertEqual(retire.call_args.args[0].pk, self.account.pk)
        self.assertEqual(retire.call_args.args[1].pk, self.target.pk)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "failed")
        self.assertEqual(self._programs("source"), [])


class RecoverySelectionTests(BarrierCase):
    def _restored_name(self):
        migration, token = self._held("verifying", contract="recovery", restore_issued=True)
        AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        self.target_domain = seed_restored(self.target_gateway, self.account, enabled=False)
        return migration, token

    def test_mail_enabled_archives_are_refused_before_any_transfer(self):
        # The hosted-mail lifecycle cannot recover mailboxes yet, and the policy step after the
        # ownership commit refuses mail; selection and transfer refuse it before anything changes.
        mail_archive = {**manifest(self.account), "domain_features": ["unix", "dir", "web", "mail"]}
        refused = select_recovery_backups(self.account, [mail_archive])
        self.assertTrue(refused.is_err())
        self.assertIn("Mail-enabled", refused.unwrap_err())

    def test_a_restored_mail_domain_is_refused_before_ownership_commit(self):
        # An archive without a recorded feature list is checked against what was actually restored.
        migration, token = self._restored_name()
        self.target_domain.features = ["unix", "dir", "web", "mail"]
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        with (
            patch("apps.provisioning.virtualmin_recovery_service.ensure_on_recreated_node", return_value=Ok(ready)),
            self.assertRaisesRegex(ValueError, "Mail-enabled"),
        ):
            VirtualminRecoveryService()._verify(migration, token)
        migration.refresh_from_db()
        self.account.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)
        self.assertEqual(self.account.server_id, self.server.pk)

    def test_recovery_requires_neutral_http_proof_before_ownership_commit(self):
        migration, token = self._restored_name()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=False)
        with (
            patch("apps.provisioning.virtualmin_recovery_service.ensure_on_recreated_node", return_value=Ok(ready)),
            self.assertRaisesRegex(ValueError, "account name"),
        ):
            VirtualminRecoveryService()._verify(migration, token)
        migration.refresh_from_db()
        self.assertIsNone(migration.cutover_committed_at)

    def test_recovery_keeps_previews_off_after_the_public_suffix_entry_ships(self):
        migration, token = self._restored_name()
        self.settings_values["dns.account_zone_psl_shipped"] = True
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        with patch("apps.provisioning.virtualmin_recovery_service.ensure_on_recreated_node", return_value=Ok(ready)):
            VirtualminRecoveryService()._verify(migration, token)
        migration.refresh_from_db()
        self.assertIsNotNone(migration.cutover_committed_at)

    def test_recovery_reapplies_current_quotas_after_restore_before_ownership_commit(self):
        migration, token = self._held("verifying", contract="recovery", restore_issued=True)
        self.account.disk_quota_mb = 2048
        self.account.bandwidth_quota_mb = -1
        self.account.save(update_fields=["disk_quota_mb", "bandwidth_quota_mb"])
        migration.account = self.account
        AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        seed_restored(self.target_gateway, self.account, enabled=False)
        self.events.clear()
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        with patch("apps.provisioning.virtualmin_recovery_service.ensure_on_recreated_node", return_value=Ok(ready)):
            VirtualminRecoveryService()._verify(migration, token)
        commands = [event for event in self.events if event[1] == "modify-domain"]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0], "target")
        self.assertEqual(commands[0][2], {"domain": self.account.domain, "quota": "2097152", "bw": "0"})
        migration.refresh_from_db()
        self.assertIsNotNone(migration.cutover_committed_at)

    def test_recovery_quota_refusal_prevents_ownership_commit(self):
        migration, token = self._held("verifying", contract="recovery", restore_issued=True)
        self.account.disk_quota_mb = 2048
        self.account.save(update_fields=["disk_quota_mb"])
        migration.account = self.account
        AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        seed_restored(self.target_gateway, self.account, enabled=False)
        self.effects[("target", "modify-domain")] = self._error("target", "modify-domain")
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        with (
            patch("apps.provisioning.virtualmin_recovery_service.ensure_on_recreated_node", return_value=Ok(ready)),
            self.assertRaisesRegex(RuntimeError, "injected failure"),
        ):
            VirtualminRecoveryService()._verify(migration, token)
        self.account.refresh_from_db()
        migration.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertIsNone(migration.cutover_committed_at)

    def test_precommit_abandonment_removes_only_the_idle_owned_target_before_unlocking(self):
        archive = "virtualmin_backup_" + "b" * 32 + ".tar.gz"
        migration, token = self._held(
            "needs_review",
            contract="recovery",
            restore_issued=True,
            barrier_state={"target_domain_id": "42", "recovery_archives": [{"archive_name": archive}]},
        )
        migration.transition(token, "needs_review", "needs_review", lease_token=None, worker_lease_expires_at=None)
        seed_restored(self.target_gateway, self.account, enabled=False)
        live = VirtualminRecoveryService()._domain(self.target, self.account.domain)
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            barrier_state={**migration.barrier_state, "target_domain_id": str(live["attributes"]["ID"])}
        )
        migration.refresh_from_db()
        self.events.clear()
        with (
            patch(
                "apps.provisioning.virtualmin_recovery_service.run_barrier", return_value=Ok(BarrierStep("ok", "idle"))
            ),
            patch(
                "apps.provisioning.virtualmin_recovery_service.run_pair_step",
                return_value=Ok(
                    PairStepResult(outcome="released", reason="barrier_removed", ran=False, checkpoints=())
                ),
            ),
            patch.object(
                VirtualminBackupService, "remove_staged_archive", autospec=True, return_value=Ok(None)
            ) as cleanup,
            patch("apps.provisioning.virtualmin_recovery_service.cleanup_held_target") as held_cleanup,
        ):
            result = resolve_migration(migration, resolved_by=self.staff, note="Abandon the incomplete restore")
        self.assertTrue(result.is_ok(), result)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "failed")
        self.assertIsNone(self.target_gateway.domain_state_of(self.account.domain))
        self.assertEqual(self._programs("source"), [])
        self.assertEqual(cleanup.call_args.args[0].server.pk, self.target.pk)
        self.assertEqual(cleanup.call_args.args[1], archive)
        held_cleanup.assert_called_once()

    def test_a_failed_push_retains_the_exact_remote_archive_intent_for_abandonment(self):
        migration, token = self._held("fetching", contract="recovery", barrier_state={"recovery_backups": ["b" * 32]})
        metadata = {
            **manifest(self.account),
            "archive_name": "virtualmin_backup_" + "f" * 32 + ".tar.gz",
            "checksum_sha256": "c" * 64,
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / metadata["archive_name"]
            path.write_bytes(b"verified archive")
            with (
                patch.object(
                    VirtualminBackupService, "_download_backup_to_spool", return_value=Ok((str(path), metadata))
                ),
                patch.object(VirtualminBackupService, "_push_archive_to_target", return_value=Err("partial upload")),
                patch("apps.provisioning.virtualmin_recovery_service.release_spool_reservation"),
                self.assertRaisesRegex(ValueError, "partial upload"),
            ):
                VirtualminRecoveryService()._transfer(migration, token)
        migration.refresh_from_db()
        self.assertEqual(migration.barrier_state["recovery_transfer_intent"]["archive_name"], metadata["archive_name"])

    def test_recovery_removes_target_archives_before_releasing_the_operation(self):
        names = ["virtualmin_backup_" + letter * 32 + ".tar.gz" for letter in ("b", "d")]
        migration, token = self._held(
            "repointing",
            contract="recovery",
            cutover_committed_at=timezone.now(),
            barrier_state={"recovery_archives": [{"archive_name": name} for name in names]},
        )
        service = VirtualminRecoveryService()
        with patch.object(
            VirtualminBackupService,
            "remove_staged_archive",
            autospec=True,
            side_effect=[Ok(None), Err("node unavailable")],
        ) as remove:
            with self.assertRaises(MigrationDeferredError):
                service._prepare_completion(migration, token)
            self.assertTrue(all(call.args[0].server.pk == self.target.pk for call in remove.call_args_list))
        migration.refresh_from_db()
        self.assertEqual(migration.status, "repointing")
        with patch.object(
            VirtualminBackupService, "remove_staged_archive", autospec=True, return_value=Ok(None)
        ) as remove:
            service._prepare_completion(migration, token)
            self.assertEqual([call.args[1] for call in remove.call_args_list], names[1:])

    def test_pair_transfers_checkpoint_between_archives_to_fit_the_worker_budget(self):
        migration, token = self._held(
            "fetching", contract="recovery", barrier_state={"recovery_backups": ["b" * 32, "d" * 32]}
        )
        base = {
            **manifest(self.account, role="base"),
            "archive_name": "virtualmin_backup_" + "b" * 32 + ".tar.gz",
            "checksum_sha256": "c" * 64,
        }
        differential = {
            **manifest(self.account, backup_id="d" * 32, role="differential"),
            "base_backup_id": base["backup_id"],
            "fp_before": base["fp_after"],
            "archive_name": "virtualmin_backup_" + "d" * 32 + ".tar.gz",
            "checksum_sha256": "e" * 64,
        }
        with TemporaryDirectory() as directory:

            def download(_store, backup_id):
                metadata = base if backup_id == base["backup_id"] else differential
                path = Path(directory) / metadata["archive_name"]
                path.write_bytes(b"verified archive")
                return Ok((str(path), metadata))

            with (
                patch.object(
                    VirtualminBackupService, "_download_backup_to_spool", autospec=True, side_effect=download
                ) as fetch,
                patch.object(VirtualminBackupService, "_push_archive_to_target", return_value=Ok(None)),
                patch("apps.provisioning.virtualmin_recovery_service.release_spool_reservation"),
            ):
                service = VirtualminRecoveryService()
                with self.assertRaises(MigrationDeferredError):
                    service._transfer(migration, token)
                self.assertEqual(fetch.call_count, 1)
                migration.refresh_from_db()
                self.assertEqual(migration.status, "fetching")
                service._transfer(migration, token)
                self.assertEqual(fetch.call_count, 2)
                self.assertEqual(migration.status, "restoring")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_verified_downloads_are_removed_and_reservations_belong_to_this_recovery(self):
        migration, token = self._held("fetching", contract="recovery", barrier_state={"recovery_backups": ["b" * 32]})
        metadata = {
            **manifest(self.account),
            "archive_name": "virtualmin_backup_" + "b" * 32 + ".tar.gz",
            "checksum_sha256": "c" * 64,
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / metadata["archive_name"]
            path.write_bytes(b"verified archive")
            with (
                patch.object(
                    VirtualminBackupService,
                    "_download_backup_to_spool",
                    autospec=True,
                    return_value=Ok((str(path), metadata)),
                ) as download,
                patch.object(VirtualminBackupService, "_push_archive_to_target", return_value=Ok(None)),
                patch("apps.provisioning.virtualmin_recovery_service.release_spool_reservation") as release,
            ):
                VirtualminRecoveryService()._transfer(migration, token)
            self.assertFalse(path.exists())
            self.assertEqual(download.call_args.args[0]._progress_key, str(migration.pk))
            release.assert_called_once_with(metadata["archive_name"])

    def test_activation_replay_accepts_an_already_enabled_target_without_changing_its_password(self):
        migration, token = self._held(
            "activating",
            contract="recovery",
            cutover_committed_at=timezone.now(),
            barrier_state={"target_domain_id": "17919754553304"},
        )
        seed_restored(self.target_gateway, self.account, enabled=True)
        # A committed activation checkpoint already owns the target in PRAHO.
        self.account.server = self.target
        self.account.save(update_fields=["server", "updated_at"])
        migration.barrier_state["target_domain_id"] = str(
            VirtualminRecoveryService()._domain(self.target, self.account.domain)["attributes"]["ID"]
        )
        VirtualminMigration.objects.filter(pk=migration.pk).update(barrier_state=migration.barrier_state)
        service = VirtualminRecoveryService()
        released = PairStepResult(outcome="released", reason="barrier_removed", ran=False, checkpoints=())
        with (
            patch.object(service, "_node"),
            patch("apps.provisioning.migration_target_hold.run_held_target_node") as policy,
            patch.object(service, "_command", side_effect=AssertionError("Target activation must not be repeated")),
            patch("apps.provisioning.virtualmin_recovery_service.run_pair_step", return_value=Ok(released)),
        ):
            service._activate(migration, token)
        policy.assert_called_once_with(migration, "reconcile_policy", enabled=True)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "repointing")

    def test_command_is_read_only_by_default_and_apply_requires_fencing(self):
        output = StringIO()
        with (
            patch(
                "apps.provisioning.virtualmin_recovery_service.VirtualminBackupService.list_backups",
                return_value=Ok([manifest(self.account)]),
            ),
            patch.object(VirtualminRecoveryService, "start_recovery") as start,
        ):
            call_command(
                "virtualmin_recover_node", source_server=self.server.pk, target_server=self.target.pk, stdout=output
            )
            self.assertIn("Dry run: 1 account", output.getvalue())
            start.assert_not_called()
            with self.assertRaises(CommandError):
                call_command(
                    "virtualmin_recover_node", source_server=self.server.pk, target_server=self.target.pk, apply=True
                )
        self.assertFalse(VirtualminMigration.objects.exists())
        self.assertEqual(self.events, [])

    def test_latest_differential_pins_its_exact_base(self):
        base = manifest(self.account, role="base")
        differential = {
            **manifest(self.account, backup_id="d" * 32, role="differential"),
            "created_at": "2026-10-27T01:00:00+00:00",
            "base_backup_id": base["backup_id"],
            "fp_before": base["fp_after"],
        }
        result = select_recovery_backups(self.account, [differential, base])
        self.assertEqual(result.unwrap(), [base["backup_id"], differential["backup_id"]])
        for corrupted in ({"fp_before": "another-base"}, {"base_backup_id": "f" * 32}):
            with self.subTest(corrupted=corrupted):
                self.assertTrue(select_recovery_backups(self.account, [{**differential, **corrupted}, base]).is_err())

    def test_incomplete_or_foreign_archives_are_refused(self):
        good = manifest(self.account)
        self.assertEqual(select_recovery_backups(self.account, [good]).unwrap(), [good["backup_id"]])
        for changed in ({"include_files": False}, {"praho_service_id": "another-customer"}, {"status": "failed"}):
            with self.subTest(changed=changed):
                self.assertTrue(select_recovery_backups(self.account, [{**good, **changed}]).is_err())

    def test_recovery_admission_requires_source_fencing_and_keeps_both_owners(self):
        name = AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        service = VirtualminRecoveryService()
        result = service.start_recovery(
            self.account, self.target, backup_ids=["b" * 32], source_fenced="", enqueue=False
        )
        self.assertTrue(result.is_err())
        self.assertFalse(VirtualminMigration.objects.exists())
        result = service.start_recovery(
            self.account,
            self.target,
            backup_ids=["b" * 32],
            source_fenced="provider power-off confirmed",
            enqueue=False,
        )
        self.assertTrue(result.is_ok(), result)
        self.account.refresh_from_db()
        name.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertEqual(name.target_server_id, self.server.pk)
        self.assertEqual(result.unwrap().barrier_state["recovery_backups"], ["b" * 32])
        self.assertEqual(self._programs("source"), [])
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "disabled")

    def test_recovery_without_the_existing_live_name_is_refused_before_mutating_either_node(self):
        self.events.clear()
        result = VirtualminRecoveryService().start_recovery(
            self.account, self.target, backup_ids=["b" * 32], source_fenced="provider confirms power off", enqueue=False
        )
        self.assertTrue(result.is_err())
        self.assertIn("name", result.unwrap_err().lower())
        self.assertFalse(VirtualminMigration.objects.exists())
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")
        self.assertEqual(self.events, [])

    def test_precommit_resolution_cannot_unlock_an_unproven_recovery_target(self):
        migration, token = self._held(
            "needs_review",
            contract="recovery",
            restore_issued=True,
            barrier_state={"target_domain_id": "17919754553304"},
        )
        migration.transition(token, "needs_review", "needs_review", lease_token=None, worker_lease_expires_at=None)
        seed_restored(self.target_gateway, self.account, enabled=False)
        with patch(
            "apps.provisioning.virtualmin_recovery_service.run_barrier", return_value=Err("unknown"), create=True
        ):
            result = resolve_migration(migration, resolved_by=self.staff, note="Investigate the partial target")
        self.assertTrue(result.is_err(), result)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "needs_review")
        self.assertIsNone(migration.lease_token)
        self.assertNotIn("delete-domain", self._programs("target"))

    def test_verified_recovery_commits_without_a_source_call_or_bridge(self):
        migration, token = self._held("verifying", contract="recovery", restore_issued=True)
        snapshot = deepcopy(migration.pre_migration_snapshot)
        snapshot["remote"]["attributes"] = {}
        VirtualminMigration.objects.filter(pk=migration.pk).update(pre_migration_snapshot=snapshot)
        migration.refresh_from_db()
        name = AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="a1b2c3d4", zone="accounts.example.net"
        )
        seed_restored(self.target_gateway, self.account, enabled=False)
        self.events.clear()  # _held uses normal migration admission to construct the fixture.
        self.effects[("source", "list-domains")] = AssertionError("Recovery must never contact the source")
        ready = EnsureOutcome(created=True, enabled=False, linked=False, certificate_installed=True, neutral=True)
        with patch("apps.provisioning.virtualmin_recovery_service.ensure_on_recreated_node", return_value=Ok(ready)):
            VirtualminRecoveryService()._verify(migration, token)
        self.account.refresh_from_db()
        name.refresh_from_db()
        migration.refresh_from_db()
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertEqual(name.target_server_id, self.target.pk)
        self.assertIsNotNone(migration.cutover_committed_at)
        self.assertFalse(MigrationBridge.objects.exists())
        self.assertEqual(self._programs("source"), [])
        self.assertNotIn("enable-domain", self._programs("target"))
