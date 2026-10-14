"""Chain state: who may break, start and extend a differential chain, and when.

The account row is the only place chain state lives. Admission of anything that can reset or
lose the node's snapshot (a restore, a new base, a migration, a delete) clears it first, in
the same transaction that creates the job; a base is linked only by a token-fenced
transaction after its archive and manifest are published; a differential is pinned to the
base and epoch it was admitted against.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import patch

from apps.common.types import Err, Ok, Retriability, retriability_of
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import (
    CHAIN_ROLE_BASE,
    CHAIN_ROLE_DIFFERENTIAL,
    BackupConfig,
    ChainContext,
    RestoreConfig,
    VirtualminBackupService,
)
from apps.provisioning.virtualmin_chain import complete_chain_job
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.provisioning.test_virtualmin_account_exclusion import ExclusionCase
from tests.provisioning.test_virtualmin_chain_playbook import SNAP_A, SNAP_B, TOKEN, result_line
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class ChainFixtures:
    """Helpers shared by the chain tests (mixed into a TestCase that has self.server)."""

    def enable_incremental_backups(self) -> None:
        from apps.settings.services import SettingsService  # noqa: PLC0415

        assert SettingsService.update_setting("provisioning.incremental_backups_enabled", True).is_ok()

    def live_chain(self, account: VirtualminAccount, *, epoch: int = 2, fingerprint: str = SNAP_A) -> Any:
        base = VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=account,
            server=account.server,
            status="completed",
            parameters={"chain_role": CHAIN_ROLE_BASE},
            result={"backup_id": "base-1", "fp_after": fingerprint, "chain_role": CHAIN_ROLE_BASE},
        )
        VirtualminAccount.objects.filter(pk=account.pk).update(
            chain_base=base, chain_base_fingerprint=fingerprint, chain_epoch=epoch
        )
        account.refresh_from_db()
        return base


class AdmissionTransitionTests(ChainFixtures, ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.enable_incremental_backups()
        self.management = VirtualminBackupManagementService(self.server)

    def admit(self, role: str) -> Any:
        with patch("django_q.tasks.async_task"):
            return self.management.create_backup_job(self.account, BackupConfig(chain_role=role))

    def test_a_base_clears_the_chain_before_it_is_dispatched(self) -> None:
        self.live_chain(self.account, epoch=2)
        job = self.admit(CHAIN_ROLE_BASE).unwrap()
        self.account.refresh_from_db()
        self.assertIsNone(self.account.chain_base)
        self.assertEqual((self.account.chain_base_fingerprint, self.account.chain_epoch), ("", 3))
        self.assertEqual(job.parameters["chain_epoch"], 3)
        self.assertRegex(job.parameters["chain_token"], r"^[0-9a-f-]{36}$")

    def test_a_differential_is_pinned_to_the_base_and_epoch_it_was_admitted_against(self) -> None:
        base = self.live_chain(self.account, epoch=2)
        job = self.admit(CHAIN_ROLE_DIFFERENTIAL).unwrap()
        self.assertEqual(
            {k: job.parameters[k] for k in ("chain_epoch", "base_job_id", "base_backup_id", "expected_fp")},
            {"chain_epoch": 2, "base_job_id": str(base.pk), "base_backup_id": "base-1", "expected_fp": SNAP_A},
        )
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base_id, self.account.chain_epoch), (base.pk, 2))

    def test_a_differential_needs_a_live_base(self) -> None:
        refused = self.admit(CHAIN_ROLE_DIFFERENTIAL)
        self.assertTrue(refused.is_err(), refused)
        self.assertIn("base", refused.unwrap_err())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_a_differential_is_refused_when_its_base_left_no_evidence(self) -> None:
        base = self.live_chain(self.account)
        VirtualminProvisioningJob.objects.filter(pk=base.pk).update(result={})
        self.assertTrue(self.admit(CHAIN_ROLE_DIFFERENTIAL).is_err())
        VirtualminProvisioningJob.objects.filter(pk=base.pk).update(result={"backup_id": "base-1", "fp_after": SNAP_B})
        self.assertTrue(self.admit(CHAIN_ROLE_DIFFERENTIAL).is_err(), "base evidence must match the account's pin")

    def test_a_restore_clears_the_chain(self) -> None:
        self.live_chain(self.account, epoch=2)
        with patch("django_q.tasks.async_task"):
            restored = self.management.create_restore_job(self.account, RestoreConfig(backup_id="b-1"))
        self.assertTrue(restored.is_ok(), restored)
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base, self.account.chain_epoch), (None, 3))

    def test_a_standalone_backup_leaves_the_chain_alone(self) -> None:
        base = self.live_chain(self.account, epoch=2)
        with patch("django_q.tasks.async_task"):
            self.assertTrue(self.management.create_backup_job(self.account).is_ok())
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base_id, self.account.chain_epoch), (base.pk, 2))

    def test_a_refused_admission_does_not_clear_the_chain(self) -> None:
        base = self.live_chain(self.account, epoch=2)
        self._job(self.account, "backup_domain", "running")
        self.assertTrue(self.admit(CHAIN_ROLE_BASE).is_err())
        with patch("django_q.tasks.async_task"):
            self.assertTrue(self.management.create_restore_job(self.account, RestoreConfig(backup_id="b")).is_err())
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base_id, self.account.chain_epoch), (base.pk, 2))

    def test_a_delete_clears_the_chain(self) -> None:
        self.live_chain(self.account, epoch=2)
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="error")
        self.account.refresh_from_db()
        self.assertIs(self.provisioning.delete_account(self.account).unwrap(), True)
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base, self.account.chain_epoch), (None, 3))

    def test_a_delete_retry_clears_the_chain(self) -> None:
        self.live_chain(self.account, epoch=2)
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="error")
        self.account.refresh_from_db()
        from tests.provisioning.test_cov_virtualmin_tasks_operations import force_status  # noqa: PLC0415

        force_status(self.service, "terminated")
        retried = self._job(self.account, "delete_domain", "running")
        self.assertIs(self.provisioning.retry_job(retried).unwrap(), True)
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base, self.account.chain_epoch), (None, 3))


class MigrationClearsTheChainTests(ChainFixtures, MigrationTestBase):
    def test_starting_a_migration_clears_the_chain(self) -> None:
        from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService  # noqa: PLC0415

        self.live_chain(self.account, epoch=4)
        started = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff, enqueue=False
        )
        self.assertTrue(started.is_ok(), started)
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base, self.account.chain_epoch), (None, 5))


class DispatchRevalidationTests(ChainFixtures, ExclusionCase):
    """The runner re-reads the chain right before it dispatches; a moved pin dispatches nothing."""

    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.backups = VirtualminBackupService(self.server)

    def prepare(self, chain: ChainContext, role: str) -> Any:
        with patch.object(self.backups, "_read_domain_id") as read_id:
            read_id.return_value = Ok("17919754553303")
            return self.backups._prepare_chain_dispatch(self.account, BackupConfig(chain_role=role, chain=chain), {}, None)

    def test_a_matching_pin_dispatches(self) -> None:
        base = self.live_chain(self.account, epoch=2)
        chain = ChainContext(token=TOKEN, epoch=2, base_job_id=str(base.pk), base_backup_id="base-1", expected_fp=SNAP_A)
        self.assertTrue(self.prepare(chain, CHAIN_ROLE_DIFFERENTIAL).is_ok())
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            chain_base=None, chain_base_fingerprint="", chain_epoch=3
        )
        self.assertTrue(self.prepare(ChainContext(token=TOKEN, epoch=3), CHAIN_ROLE_BASE).is_ok())

    def test_a_moved_pin_dispatches_nothing(self) -> None:
        base = self.live_chain(self.account, epoch=2)
        chain = ChainContext(token=TOKEN, epoch=2, base_job_id=str(base.pk), base_backup_id="base-1", expected_fp=SNAP_A)
        for label, changes in (
            ("epoch", {"chain_epoch": 3}),
            ("base", {"chain_base": None}),
            ("fingerprint", {"chain_base_fingerprint": SNAP_B}),
        ):
            with self.subTest(moved=label):
                VirtualminAccount.objects.filter(pk=self.account.pk).update(**changes)
                refused = self.prepare(chain, CHAIN_ROLE_DIFFERENTIAL)
                self.assertTrue(refused.is_err(), refused)
                self.assertEqual(retriability_of(refused), Retriability.NOT_RETRIABLE)
                self.live_chain(self.account, epoch=2)


class EvidenceInvalidationTests(ChainFixtures, ExclusionCase):
    """A node step that shows the snapshot is gone or moved ends the live chain (epoch-fenced)."""

    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.backups = VirtualminBackupService(self.server)
        self.base = self.live_chain(self.account, epoch=2)

    def run_step(self, **overrides: Any) -> Any:
        chain = ChainContext(
            token=TOKEN, epoch=2, base_job_id=str(self.base.pk), base_backup_id="base-1", expected_fp=SNAP_A
        )
        line = result_line(mode="differential", **overrides)
        metadata = {"virtualmin_domain_id": "17919754553303", "archive_name": "virtualmin_backup_" + "c" * 32 + ".tar.gz"}
        from types import SimpleNamespace  # noqa: PLC0415

        played = Ok(SimpleNamespace(success=True, stdout=line, return_code=0))
        config = BackupConfig(chain_role=CHAIN_ROLE_DIFFERENTIAL, chain=chain)
        with patch.object(self.backups, "run_chain_step", wraps=self.backups.run_chain_step), patch(
            "apps.infrastructure.ansible_service.AnsibleService"
        ) as ansible, patch.object(type(self.server), "node_deployment", create=True, new=object()):
            ansible.return_value.run_playbook.return_value = played
            return self.backups._execute_chain_backup(self.account, "b", metadata, config)

    def chain_state(self) -> tuple[Any, int]:
        self.account.refresh_from_db()
        return self.account.chain_base_id, self.account.chain_epoch

    def test_a_fingerprint_mismatch_ends_the_chain(self) -> None:
        result = self.run_step(outcome="refused", reason="fingerprint_mismatch", ran=False, sha256="", size=0, fp_after="")
        self.assertTrue(result.is_err(), result)
        self.assertEqual(self.chain_state(), (None, 3))

    def test_a_differential_that_moved_the_snapshot_ends_the_chain(self) -> None:
        self.run_step(outcome="failed", reason="snapshot_changed", fp_before=SNAP_A, fp_after=SNAP_B, sha256="", size=0)
        self.assertEqual(self.chain_state(), (None, 3))

    def test_refusals_that_say_nothing_about_the_snapshot_keep_the_chain(self) -> None:
        for reason in ("lock_busy", "cancelled"):
            with self.subTest(reason=reason):
                self.run_step(outcome="refused", reason=reason, ran=False, sha256="", size=0, fp_after="")
                self.assertEqual(self.chain_state(), (self.base.pk, 2))

    def test_a_failed_differential_that_left_the_snapshot_alone_keeps_the_chain(self) -> None:
        self.run_step(outcome="failed", reason="backup_command_failed", fp_before=SNAP_A, fp_after=SNAP_A, sha256="", size=0)
        self.assertEqual(self.chain_state(), (self.base.pk, 2))

    def test_a_newer_chain_is_never_cleared_by_an_older_job(self) -> None:
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_epoch=7)
        self.run_step(outcome="refused", reason="fingerprint_mismatch", ran=False, sha256="", size=0, fp_after="")
        self.assertEqual(self.chain_state(), (self.base.pk, 7))


class FencedCompletionTests(ChainFixtures, ExclusionCase):
    """The base is linked and the job completed in ONE transaction, fenced by token and epoch."""

    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_epoch=3)
        self.account.refresh_from_db()

    def make_job(self, role: str, **params: Any) -> tuple[VirtualminProvisioningJob, Any]:
        token = uuid.uuid4()
        job = VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            status="running",
            execution_token=token,
            parameters={"chain_role": role, "chain_epoch": 3, **params},
        )
        return job, token

    def finish(self, job: VirtualminProvisioningJob, token: Any, **result: Any) -> str:
        outcome = {"backup_id": "new-1", "fp_before": SNAP_B, "fp_after": SNAP_A, **result}
        return complete_chain_job(job, token, outcome)

    def state(self, job: VirtualminProvisioningJob) -> tuple[Any, str, int, str]:
        self.account.refresh_from_db()
        job.refresh_from_db()
        return self.account.chain_base_id, self.account.chain_base_fingerprint, self.account.chain_epoch, job.status

    def test_a_base_is_linked_and_completed_together(self) -> None:
        job, token = self.make_job(CHAIN_ROLE_BASE)
        self.assertEqual(self.finish(job, token), "completed")
        self.assertEqual(self.state(job), (job.pk, SNAP_A, 3, "completed"))
        self.assertEqual(job.result["backup_id"], "new-1")

    def test_a_base_without_a_fresh_snapshot_is_not_linked(self) -> None:
        for label, result in (("unchanged", {"fp_after": SNAP_B}), ("absent", {"fp_after": "ABSENT"}), ("empty", {"fp_after": ""})):
            with self.subTest(snapshot=label):
                job, token = self.make_job(CHAIN_ROLE_BASE)
                self.assertEqual(self.finish(job, token, **result), "attention")
                self.assertEqual(self.state(job), (None, "", 3, "attention"))

    def test_a_base_whose_epoch_moved_is_published_but_not_linked(self) -> None:
        job, token = self.make_job(CHAIN_ROLE_BASE)
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_epoch=4)
        self.assertEqual(self.finish(job, token), "attention")
        self.assertEqual(self.state(job), (None, "", 4, "attention"))

    def test_a_superseded_runner_changes_nothing(self) -> None:
        job, _token = self.make_job(CHAIN_ROLE_BASE)
        self.assertEqual(self.finish(job, uuid.uuid4()), "superseded")
        self.assertEqual(self.state(job), (None, "", 3, "running"))

    def test_losing_the_job_at_the_last_moment_rolls_the_link_back(self) -> None:
        """The token check passed, then the terminal write matched nothing: the link must not survive."""
        job, token = self.make_job(CHAIN_ROLE_BASE)
        with patch.object(VirtualminProvisioningJob, "finish_execution", return_value=0):
            self.assertEqual(self.finish(job, token), "superseded")
        self.assertEqual(self.state(job), (None, "", 3, "running"))

    def test_a_differential_completes_without_touching_the_chain(self) -> None:
        base = self.live_chain(self.account, epoch=3)
        job, token = self.make_job(
            CHAIN_ROLE_DIFFERENTIAL, base_job_id=str(base.pk), base_backup_id="base-1", expected_fp=SNAP_A
        )
        self.assertEqual(self.finish(job, token, fp_before=SNAP_A, fp_after=SNAP_A), "completed")
        self.assertEqual(self.state(job), (base.pk, SNAP_A, 3, "completed"))

    def test_a_differential_whose_chain_moved_is_published_but_parked(self) -> None:
        base = self.live_chain(self.account, epoch=3)
        job, token = self.make_job(
            CHAIN_ROLE_DIFFERENTIAL, base_job_id=str(base.pk), base_backup_id="base-1", expected_fp=SNAP_A
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_base=None, chain_epoch=4)
        self.assertEqual(self.finish(job, token, fp_before=SNAP_A, fp_after=SNAP_A), "attention")
        self.assertEqual(self.state(job), (None, SNAP_A, 4, "attention"))


class RunnerChainWiringTests(ChainFixtures, ExclusionCase):
    """run_virtualmin_backup rebuilds the pins from the job and finishes through the fenced path."""

    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.enable_incremental_backups()
        self.management = VirtualminBackupManagementService(self.server)

    def admit_and_run(self, role: str, outcome: Any) -> tuple[VirtualminProvisioningJob, list[BackupConfig]]:
        with patch("django_q.tasks.async_task"):
            job = self.management.create_backup_job(self.account, BackupConfig(chain_role=role)).unwrap()
        seen: list[BackupConfig] = []

        def backup(self: VirtualminBackupService, account: object, config: BackupConfig, **kwargs: object) -> Any:
            seen.append(config)
            return outcome

        with patch.object(VirtualminBackupService, "backup_domain", autospec=True, side_effect=backup):
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        job.refresh_from_db()
        self.account.refresh_from_db()
        return job, seen

    def test_a_base_job_links_the_chain_when_its_backup_succeeds(self) -> None:
        job, seen = self.admit_and_run(
            CHAIN_ROLE_BASE, Ok({"backup_id": "new-1", "fp_before": SNAP_B, "fp_after": SNAP_A})
        )
        self.assertEqual(job.status, "completed")
        self.assertEqual((self.account.chain_base_id, self.account.chain_base_fingerprint), (job.pk, SNAP_A))
        (config,) = seen
        assert config.chain is not None
        self.assertEqual((config.chain_role, config.chain.epoch, config.chain.token), ("base", 1, job.parameters["chain_token"]))

    def test_a_failed_base_leaves_the_chain_empty(self) -> None:
        job, _ = self.admit_and_run(CHAIN_ROLE_BASE, Err("node refused", retriability=Retriability.NOT_RETRIABLE))
        self.assertEqual(job.status, "failed")
        self.assertIsNone(self.account.chain_base)

    def test_a_differential_job_gets_its_pins(self) -> None:
        base = self.live_chain(self.account, epoch=2)
        job, seen = self.admit_and_run(CHAIN_ROLE_DIFFERENTIAL, Ok({"backup_id": "d-1", "fp_before": SNAP_A, "fp_after": SNAP_A}))
        self.assertEqual(job.status, "completed")
        (config,) = seen
        assert config.chain is not None
        self.assertEqual(
            (config.chain.epoch, config.chain.base_job_id, config.chain.base_backup_id, config.chain.expected_fp),
            (2, str(base.pk), "base-1", SNAP_A),
        )
        self.assertEqual(self.account.chain_base_id, base.pk)


class ManifestReaderGuardTests(ChainFixtures, ExclusionCase):
    """A restore reads the manifest's lineage fields; what it cannot place safely is refused.

    A differential holds only the files changed since its base (contract Q7): restored alone it
    would recreate a domain with most of its files missing. Pair restore reads the lineage;
    until it does, a differential is not restorable on its own, and a manifest from a future
    format is never read as a legacy standalone backup.
    """

    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.backups = VirtualminBackupService(self.server)

    def restore(self, **manifest: Any) -> Any:
        metadata = {
            "archive_name": "virtualmin_backup_" + "b" * 32 + ".tar.gz",
            "checksum_sha256": "0" * 64,
            "praho_service_id": str(self.account.service_id),
            "domain": self.account.domain,
            **manifest,
        }
        with (
            patch.object(self.backups, "_download_backup_to_spool", return_value=Ok(("/nonexistent/x.tar.gz", metadata))),
            patch.object(self.backups, "_target_domain_gate", return_value=Err("reached the target gate")) as gate,
        ):
            result = self.backups.restore_domain(self.account, RestoreConfig(backup_id="r", force_restore=True))
        self.last_gate_calls = gate.call_count
        return result

    def test_unsafe_or_unknown_manifests_are_refused_before_the_target_is_touched(self) -> None:
        for label, manifest in (
            ("differential alone", {"manifest_version": 1, "chain_role": "differential", "base_backup_id": "b"}),
            ("future version", {"manifest_version": 2, "chain_role": "standalone"}),
            ("unknown role", {"manifest_version": 1, "chain_role": "mirror"}),
            ("role without version", {"chain_role": "differential"}),
        ):
            with self.subTest(manifest=label):
                result = self.restore(**manifest)
                self.assertTrue(result.is_err(), result)
                self.assertNotIn("target gate", result.unwrap_err())
                self.assertEqual(self.last_gate_calls, 0)
                self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_legacy_standalone_and_base_manifests_still_restore(self) -> None:
        for label, manifest in (
            ("legacy (no fields)", {}),
            ("legacy with a stored role", {"chain_role": "standalone"}),
            ("versioned standalone", {"manifest_version": 1, "chain_role": "standalone"}),
            ("versioned base", {"manifest_version": 1, "chain_role": "base"}),
        ):
            with self.subTest(manifest=label):
                result = self.restore(**manifest)
                self.assertEqual(self.last_gate_calls, 1, result)


class ChainBudgetTests(ChainFixtures, ExclusionCase):
    """A chain job runs two Ansible invocations (the step, then the fetch); its budget covers both."""

    def test_a_chain_admission_budget_covers_the_step_and_the_fetch(self) -> None:
        from apps.provisioning.virtualmin_backup_service import (  # noqa: PLC0415
            _SSH_SETUP_MARGIN_SECONDS,
            CHAIN_LOCK_WAIT_SECONDS,
            CHAIN_STEP_MARGIN_SECONDS,
        )
        account = self._account()
        self.enable_incremental_backups()
        management = VirtualminBackupManagementService(self.server)
        with patch("django_q.tasks.async_task"):
            standalone = management.create_backup_job(account).unwrap()
            VirtualminProvisioningJob.objects.filter(pk=standalone.pk).update(status="completed")
            base = management.take_base_backup(account).unwrap()
        extra = base.parameters["task_budget_seconds"] - standalone.parameters["task_budget_seconds"]
        self.assertEqual(extra, CHAIN_LOCK_WAIT_SECONDS + CHAIN_STEP_MARGIN_SECONDS + _SSH_SETUP_MARGIN_SECONDS)
