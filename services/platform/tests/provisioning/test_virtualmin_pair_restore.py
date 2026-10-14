"""Pair restore: lineage, admission, the workflow around the locked node step, and resolution.

The node step itself (barrier, ordering, cancel marker) is proved by test_virtualmin_pair_restore_script
and by the lab. These tests pin what PRAHO does around it: nothing destructive before the
preflight passes, the account suspended while the node step runs, every outcome mapped to a job
state, the reconcile queued only when the node is known to be in a releasable state, and the
operator's resolution releasing the node before the account.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase, override_settings

from apps.common.types import Err, Ok, Retriability
from apps.provisioning import virtualmin_pair_restore as pair
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.settings.services import SettingsService
from tests.provisioning.test_virtualmin_account_exclusion import ExclusionCase
from tests.provisioning.test_virtualmin_chain_playbook import SNAP_A, SNAP_B
from tests.provisioning.test_virtualmin_chain_state import ChainFixtures

DOMAIN_ID = "17919754553303"
BASE_ARCHIVE = "virtualmin_backup_" + "b" * 32 + ".tar.gz"
DIFF_ARCHIVE = "virtualmin_backup_" + "d" * 32 + ".tar.gz"


def manifests(account: VirtualminAccount) -> tuple[dict[str, Any], dict[str, Any]]:
    common: dict[str, Any] = {
        "manifest_version": 1,
        "status": "completed",
        "domain": account.domain,
        "praho_service_id": str(account.service_id),
        "include_email": True,
        "include_databases": True,
        "include_files": True,
        "include_ssl": True,
        "virtualmin_domain_id": DOMAIN_ID,
        "node_id": "node-1",
        "chain_epoch": 3,
        "file_size_bytes": 1_000_000,
    }
    base = {
        **common,
        "backup_id": "base-1",
        "chain_role": "base",
        "fp_before": SNAP_B,
        "fp_after": SNAP_A,
        "archive_name": BASE_ARCHIVE,
        "checksum_sha256": "b" * 64,
    }
    diff = {
        **common,
        "backup_id": "diff-1",
        "chain_role": "differential",
        "base_backup_id": "base-1",
        "fp_before": SNAP_A,
        "fp_after": SNAP_A,
        "archive_name": DIFF_ARCHIVE,
        "checksum_sha256": "d" * 64,
    }
    return base, diff


def checkpoint(step: str, *, disabled: bool = True, http80: str = "503", http443: str = "503") -> pair.PairCheckpoint:
    return pair.PairCheckpoint(step=step, at="1.0", disabled=disabled, http80=http80, http443=http443)


GOOD_CHECKPOINTS = (
    checkpoint("barrier_up"),
    checkpoint("after_base"),
    checkpoint("after_differential"),
    checkpoint("barrier_down", http80="200", http443="200"),
)


def node_result(outcome: str = "ok", reason: str = "completed", *, ran: bool = True, checkpoints: Any = GOOD_CHECKPOINTS) -> Any:
    return Ok(pair.PairStepResult(outcome=outcome, reason=reason, ran=ran, checkpoints=tuple(checkpoints)))


class PairLineageTests(ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.base, self.diff = manifests(self.account)

    def refusal(self) -> str | None:
        return pair.pair_lineage_refusal(
            self.base, self.diff, service_id=self.account.service_id, domain=self.account.domain
        )

    def test_a_base_and_the_differential_taken_against_it_are_a_pair(self) -> None:
        self.assertIsNone(self.refusal())

    def test_every_break_in_the_lineage_is_refused(self) -> None:
        breaks: dict[str, tuple[str, Any]] = {
            "second is not a differential": ("diff", {"chain_role": "base"}),
            "first is not a base": ("base", {"chain_role": "standalone"}),
            "differential of a differential": ("base", {"base_backup_id": "older"}),
            "names another base": ("diff", {"base_backup_id": "other-base"}),
            "taken against another snapshot": ("diff", {"fp_before": SNAP_B}),
            "base left no snapshot": ("base", {"fp_after": "ABSENT"}),
            "unknown manifest version": ("diff", {"manifest_version": 99}),
            "legacy manifest": ("base", {"manifest_version": None}),
            "unknown role": ("diff", {"chain_role": "mirror"}),
            "incomplete backup": ("diff", {"include_databases": False}),
            "not completed": ("base", {"status": "in_progress"}),
            "another service": ("diff", {"praho_service_id": "another"}),
            "another domain": ("base", {"domain": "other.example.com"}),
            "another domain id": ("diff", {"virtualmin_domain_id": "1"}),
            "another provenance node": ("diff", {"node_id": "node-2"}),
            "another chain epoch": ("diff", {"chain_epoch": 4}),
        }
        for label, (which, change) in breaks.items():
            with self.subTest(case=label):
                self.base, self.diff = manifests(self.account)
                (self.base if which == "base" else self.diff).update(change)
                self.assertIsNotNone(self.refusal())

    def test_the_label_states_the_two_facts_an_operator_must_know(self) -> None:
        self.assertIn("deleted after the base", str(pair.PAIR_RESTORE_LABEL))
        self.assertIn("databases come from the differential", str(pair.PAIR_RESTORE_LABEL))


class PairResultTests(SimpleTestCase):
    def test_a_result_whose_barrier_did_not_hold_is_not_believed(self) -> None:
        broken = pair.PairStepResult(
            "ok", "completed", True, (checkpoint("barrier_up"), checkpoint("after_base", http80="200"))
        )
        self.assertIn("after_base", str(broken.barrier_broken()))
        enabled_at_end = pair.PairStepResult(
            "ok", "completed", True, (checkpoint("barrier_up"), checkpoint("barrier_down", disabled=False))
        )
        self.assertIsNotNone(enabled_at_end.barrier_broken())
        self.assertIsNone(pair.PairStepResult("ok", "completed", True, GOOD_CHECKPOINTS).barrier_broken())


class PairRestoreCase(ChainFixtures, ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.base, self.diff = manifests(self.account)
        self.events: list[str] = []

        def download(service: Any, backup_id: str) -> Any:
            self.events.append(f"download {backup_id}")
            return Ok((f"/nonexistent/{backup_id}", dict(self.base if backup_id == "base-1" else self.diff)))

        def push(service: Any, server: Any, archive_name: str, sha: str) -> Any:
            self.events.append(f"push {archive_name[18:20]}")
            return self.push_result

        def node(server: Any, variables: dict[str, Any], **kwargs: Any) -> Any:
            self.events.append("node step")
            self.node_variables = variables
            self.account_status_during_step = VirtualminAccount.objects.get(pk=self.account.pk).status
            return self.node_outcome

        self.push_result: Any = Ok(None)
        self.node_outcome: Any = node_result()
        self.node_variables: dict[str, Any] = {}
        self.account_status_during_step = ""
        self.cleaned: list[str] = []
        self.reconciles: list[str] = []
        patches = [
            patch.object(VirtualminBackupService, "_download_backup_to_spool", autospec=True, side_effect=download),
            patch.object(VirtualminBackupService, "_target_domain_gate", return_value=Ok(True)),
            patch.object(VirtualminBackupService, "backup_domain", return_value=Ok({"backup_id": "safety-1"})),
            patch.object(VirtualminBackupService, "_push_archive_to_target", autospec=True, side_effect=push),
            patch.object(VirtualminBackupService, "_verify_restored_domain", return_value=Ok(None)),
            patch.object(VirtualminBackupService, "_domain_features", return_value=None),
            patch.object(
                VirtualminBackupService, "_cleanup_remote_archive", side_effect=lambda server, name: self.cleaned.append(name)
            ),
            patch.object(pair, "run_pair_step", side_effect=node),
            patch.object(
                virtualmin_tasks, "reconcile_virtualmin_service_state_async", side_effect=self.reconciles.append
            ),
            patch("django_q.tasks.async_task"),
        ]
        for active in patches:
            active.start()
            self.addCleanup(active.stop)
        self.read = patch.object(
            VirtualminBackupService,
            "read_manifest",
            side_effect=lambda backup_id: Ok(dict(self.base if backup_id == "base-1" else self.diff)),
        )
        self.read.start()
        self.addCleanup(self.read.stop)
        self.management = VirtualminBackupManagementService(self.server)

    def admit(self, **kwargs: Any) -> Any:
        kwargs.setdefault("force_restore", True)
        return self.management.create_pair_restore_job(self.account, "base-1", "diff-1", **kwargs)

    def execute(self, job: VirtualminProvisioningJob) -> VirtualminProvisioningJob:
        virtualmin_tasks.run_virtualmin_restore(str(job.pk))
        job.refresh_from_db()
        return job


class PairAdmissionTests(PairRestoreCase):
    def test_admission_pins_both_backups_invalidates_the_chain_and_sizes_the_budget(self) -> None:
        self.live_chain(self.account, epoch=2)
        job = self.admit().unwrap()
        self.assertEqual(job.operation, "restore_domain")
        self.assertEqual(
            {k: job.parameters[k] for k in ("restore_mode", "base_backup_id", "differential_backup_id")},
            {"restore_mode": "pair", "base_backup_id": "base-1", "differential_backup_id": "diff-1"},
        )
        self.assertRegex(job.parameters["pair_token"], r"^[0-9a-f-]{36}$")
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base, self.account.chain_epoch), (None, 3))
        small = job.parameters["task_budget_seconds"]
        self.base["file_size_bytes"] = 20 * 1024**3
        self.diff["file_size_bytes"] = 20 * 1024**3
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(status="failed")
        with override_settings(Q_CLUSTER={**settings.Q_CLUSTER, "retry": 10**6}):
            big = self.admit().unwrap().parameters["task_budget_seconds"]
        self.assertGreater(big, small, "the budget grows with both archives")

    def test_admission_refuses_what_the_workflow_would_refuse(self) -> None:
        self.assertTrue(self.admit(force_restore=False).is_err(), "a pair restore must be confirmed")
        self.diff["fp_before"] = SNAP_B
        refused = self.admit()
        self.assertTrue(refused.is_err())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_admission_is_refused_while_another_operation_holds_the_account(self) -> None:
        self._job(self.account, "backup_domain", "running")
        self.assertTrue(self.admit().is_err())

    def test_a_budget_that_does_not_fit_the_broker_visibility_window_is_refused(self) -> None:
        self.base["file_size_bytes"] = 500 * 1024**3
        refused = self.admit()
        self.assertTrue(refused.is_err())
        self.assertIn("visibility", refused.unwrap_err())


class PairWorkflowTests(PairRestoreCase):
    def test_a_verified_pair_restore_runs_in_order_and_leaves_the_enabling_to_reconcile(self) -> None:
        job = self.execute(self.admit().unwrap())
        self.assertEqual(job.status, "completed", job.status_message)
        self.assertEqual(
            self.events,
            ["download base-1", "download diff-1", "push bb", "push dd", "node step"],
        )
        self.assertEqual(self.account_status_during_step, "suspended", "PRAHO's view: out of service during the step")
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended", "reconcile, not the workflow, re-enables")
        self.assertEqual(self.reconciles, [str(self.account.service_id)])
        self.assertCountEqual(self.cleaned, [BASE_ARCHIVE, DIFF_ARCHIVE])
        self.assertEqual(self.node_variables["pair_base_archive"], BASE_ARCHIVE)
        self.assertEqual(self.node_variables["pair_diff_archive"], DIFF_ARCHIVE)
        self.assertEqual(len(job.result["pair_checkpoints"]), 4)
        self.assertFalse(account_has_active_operation(self.account))

    def test_nothing_destructive_happens_when_the_preflight_fails(self) -> None:
        job = self.admit().unwrap()
        self.diff["fp_before"] = SNAP_B  # the downloaded manifest differs from what admission saw
        job = self.execute(job)
        self.assertEqual(job.status, "failed")
        self.assertEqual(self.events, ["download base-1", "download diff-1"])
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "active")

    def test_a_node_refusal_leaves_the_node_and_the_account_as_they_were(self) -> None:
        self.node_outcome = node_result("refused", "barrier_not_verified", ran=False, checkpoints=())
        job = self.execute(self.admit().unwrap())
        self.assertEqual(job.status, "failed")
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "active")
        self.assertCountEqual(self.cleaned, [BASE_ARCHIVE, DIFF_ARCHIVE])
        self.assertFalse(account_has_active_operation(self.account))

    def test_any_failure_after_the_barrier_parks_the_job_with_its_checkpoints(self) -> None:
        stopped = (checkpoint("barrier_up"), checkpoint("after_base"))
        cases = {
            "stopped between the restores": node_result("failed", "cancelled_before_differential", checkpoints=stopped),
            "success claimed with a broken barrier": node_result(
                checkpoints=(checkpoint("barrier_up"), checkpoint("after_base", http80="200"))
            ),
            "result lost": Err("playbook timed out", retriability=Retriability.UNKNOWN),
        }
        for label, outcome in cases.items():
            with self.subTest(case=label):
                self.events.clear()
                self.cleaned.clear()
                self.reconciles.clear()
                VirtualminProvisioningJob.objects.all().delete()
                VirtualminAccount.objects.filter(pk=self.account.pk).update(status="active")
                self.node_outcome = outcome
                job = self.execute(self.admit().unwrap())
                self.assertEqual(job.status, "attention", job.status_message)
                self.account.refresh_from_db()
                self.assertEqual(self.account.status, "suspended", "the domain is still disabled; PRAHO agrees")
                self.assertEqual(self.reconciles, [], "reconcile must not enable a domain mid-recovery")
                self.assertEqual(self.cleaned, [], "the pushed archives are the operator's reconciliation artifact")
                self.assertTrue(account_has_active_operation(self.account))
                if label == "stopped between the restores":
                    self.assertEqual([c["step"] for c in job.parameters["pair_checkpoints"]], ["barrier_up", "after_base"])

    def test_a_superseded_runner_stops_before_it_pushes_or_restores(self) -> None:
        job = self.admit().unwrap()

        def take_over_during_safety_backup(*args: Any, **kwargs: Any) -> Any:
            VirtualminProvisioningJob.take_over_execution(job.pk, "attention", "Worker interrupted")
            return Ok({"backup_id": "safety-1"})

        with patch.object(VirtualminBackupService, "backup_domain", side_effect=take_over_during_safety_backup):
            job = self.execute(job)
        self.assertNotIn("node step", self.events)
        self.assertFalse(any(event.startswith("push") for event in self.events))
        self.assertEqual(job.status, "attention", "the takeover's verdict stands")

    def test_a_push_failure_is_definite_and_removes_what_was_pushed(self) -> None:
        results = iter([Ok(None), Err("copy failed", retriability=Retriability.NOT_RETRIABLE)])
        self.push_result = None

        def push(server: Any, name: str, sha: str) -> Any:
            self.events.append(f"push {name[18:20]}")
            return next(results)

        with patch.object(VirtualminBackupService, "_push_archive_to_target", side_effect=push):
            job = self.execute(self.admit().unwrap())
        self.assertEqual(job.status, "failed")
        self.assertNotIn("node step", self.events)
        self.assertEqual(self.cleaned, [BASE_ARCHIVE])

    def test_the_domain_must_exist_for_a_pair_restore(self) -> None:
        with patch.object(VirtualminBackupService, "_target_domain_gate", return_value=Ok(False)):
            job = self.execute(self.admit().unwrap())
        self.assertEqual(job.status, "failed")
        self.assertIn("live domain", job.status_message)
        self.assertNotIn("node step", self.events)


class PairResolutionTests(PairRestoreCase):
    def parked(self, **parameters: Any) -> VirtualminProvisioningJob:
        job = self.admit().unwrap()
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
            status="attention",
            parameters={
                **job.parameters,
                "virtualmin_domain_id": DOMAIN_ID,
                "pair_node_step": "dispatching",
                "pair_archives": [BASE_ARCHIVE, DIFF_ARCHIVE],
                **parameters,
            },
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="suspended")
        job.refresh_from_db()
        return job

    def test_the_node_is_released_before_the_account_and_reconcile_enables_the_domain(self) -> None:
        job = self.parked()
        calls: list[dict[str, Any]] = []

        def release(server: Any, variables: dict[str, Any], **kwargs: Any) -> Any:
            calls.append({"variables": variables, "job_status": VirtualminProvisioningJob.objects.get(pk=job.pk).status})
            return node_result("released", "barrier_removed", ran=False, checkpoints=())

        removed: list[str] = []
        with (
            patch.object(pair, "run_pair_step", side_effect=release),
            patch.object(VirtualminBackupService, "remove_staged_archive", side_effect=lambda name: removed.append(name) or Ok(None)),
        ):
            resolved = pair.resolve_pair_job(job, resolved_by="staff@example.com", note="checked")
        self.assertTrue(resolved.is_ok(), resolved)
        (call,) = calls
        self.assertEqual(call["variables"]["pair_action"], "release")
        self.assertEqual(call["job_status"], "attention", "the node is released first")
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertEqual(removed, [BASE_ARCHIVE, DIFF_ARCHIVE])
        self.assertEqual(self.reconciles, [str(self.account.service_id)])
        self.assertFalse(account_has_active_operation(self.account))

    def test_nothing_is_released_when_the_node_cannot_confirm(self) -> None:
        job = self.parked()
        for outcome in (Err("unreachable", retriability=Retriability.UNKNOWN), node_result("refused", "lock_busy", ran=False, checkpoints=())):
            with self.subTest(outcome=str(outcome)[:30]), patch.object(pair, "run_pair_step", return_value=outcome):
                resolved = pair.resolve_pair_job(job, resolved_by="staff", note="x")
                self.assertTrue(resolved.is_err())
                job.refresh_from_db()
                self.assertEqual(job.status, "attention")
                self.assertEqual(self.reconciles, [])

    def test_a_job_that_never_reached_the_node_needs_no_release(self) -> None:
        job = self.admit().unwrap()
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(status="attention")
        job.refresh_from_db()
        with patch.object(pair, "run_pair_step") as step:
            self.assertTrue(pair.resolve_pair_job(job, resolved_by="staff", note="x").is_ok())
        step.assert_not_called()

    def test_the_staff_resolve_view_takes_this_path_for_pair_jobs(self) -> None:
        from django.urls import reverse  # noqa: PLC0415

        from apps.users.models import User  # noqa: PLC0415

        staff = User.objects.create_user(email="pair-resolver@example.com", password="pair-test-password", staff_role="admin")
        self.client.force_login(staff)
        job = self.parked()
        with (
            patch.object(pair, "run_pair_step", return_value=node_result("released", "barrier_removed", ran=False, checkpoints=())) as step,
            patch.object(VirtualminBackupService, "remove_staged_archive", return_value=Ok(None)),
        ):
            self.client.post(reverse("provisioning:virtualmin_job_resolve", args=[job.pk]), {"note": "ok"})
        step.assert_called_once()
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertIn("pair-resolver@example.com", job.status_message)


class PairBudgetSettingsTests(PairRestoreCase):
    """The settings that size the budget and the reservation leases reach the pair restore."""

    GIB = 1024**3

    def budget(self) -> int:
        return pair.pair_restore_task_timeout(256 * 1024**2, 20 * self.GIB, 5 * self.GIB)

    def test_the_backup_timeout_sizes_the_safety_backup_and_both_restores(self) -> None:
        before = self.budget()
        SettingsService.update_setting("provisioning.migration_backup_timeout_seconds", 2800)
        # +1000 for the safety backup's own backup call, +2000 for the two restores on the node.
        self.assertEqual(self.budget() - before, 3000)

    def test_the_transfer_timeout_caps_what_each_push_may_be_budgeted(self) -> None:
        before = self.budget()
        SettingsService.update_setting("provisioning.migration_transfer_timeout_seconds", 600)
        self.assertLess(self.budget(), before)

    def test_a_faster_minimum_transfer_rate_shortens_the_downloads_and_pushes(self) -> None:
        before = self.budget()
        SettingsService.update_setting("provisioning.backup_min_transfer_mib_s", 40)
        self.assertLess(self.budget(), before)

    def test_held_archives_are_leased_for_the_transfer_timeout_plus_a_margin(self) -> None:
        from apps.provisioning.virtualmin_backup_service import RestoreConfig  # noqa: PLC0415

        SettingsService.update_setting("provisioning.migration_transfer_timeout_seconds", 1234)
        leases: list[int] = []
        config = RestoreConfig(
            backup_id="base-1", differential_backup_id="diff-1", force_restore=True, pair_token=str(uuid.uuid4())
        )
        with patch("apps.provisioning.spool.renew_spool_reservation", side_effect=lambda name, ttl: leases.append(ttl)):
            outcome = pair.restore_pair(VirtualminBackupService(self.server), self.account, config, self.server, "r-1", None)
        self.assertTrue(outcome.is_ok(), outcome)
        self.assertEqual(set(leases), {1234 + 600})
        self.assertEqual(len(leases), 4, "both held archives, before each of the two pushes")
