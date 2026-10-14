"""Chain jobs that may still be running on the node keep the account until an operator confirms.

A timeout, an ambiguous playbook error or a dead worker says nothing about whether the node
step finished, is waiting for the lock, or will start later. Those jobs go to attention and
keep the exclusion. "Confirm stopped" writes the job's cancel marker on the node under the
lock, invalidates the chain, and only then releases the exclusion.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.common.types import Err, Ok, Retriability
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import ChainStepResult, VirtualminBackupService
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.users.models import User
from tests.provisioning.test_virtualmin_account_exclusion import ExclusionCase
from tests.provisioning.test_virtualmin_chain_playbook import SNAP_A
from tests.provisioning.test_virtualmin_chain_state import ChainFixtures

DOMAIN_ID = "17919754553303"


def cancel_result(**overrides: Any) -> ChainStepResult:
    fields: dict[str, Any] = {
        "outcome": "cancelled",
        "reason": "marker_written",
        "ran": False,
        "mode": "cancel",
        "fp_before": "",
        "fp_after": "",
        "backup_rc": -1,
        "sha256": "",
        "size": 0,
        "detail": "",
        "archive": "",
    }
    return ChainStepResult(**{**fields, **overrides})


class InterruptedChainJobTests(ChainFixtures, ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.enable_incremental_backups()

    def admit_and_run(self, role: str, outcome: Any) -> VirtualminProvisioningJob:
        from apps.provisioning.virtualmin_backup_service import BackupConfig  # noqa: PLC0415

        if role == "differential":
            self.live_chain(self.account, epoch=2)
        with patch("django_q.tasks.async_task"):
            job = VirtualminBackupManagementService(self.server).create_backup_job(
                self.account, BackupConfig(chain_role=role)
            ).unwrap()
        with patch.object(VirtualminBackupService, "backup_domain", autospec=True, return_value=outcome):
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        job.refresh_from_db()
        return job

    def test_an_uncertain_chain_step_parks_the_job_and_keeps_the_exclusion(self) -> None:
        for role in ("base", "differential"):
            with self.subTest(role=role):
                job = self.admit_and_run(role, Err("playbook timed out", retriability=Retriability.UNKNOWN))
                self.assertEqual(job.status, "attention")
                self.assertTrue(account_has_active_operation(self.account))
                refused = VirtualminBackupManagementService(self.server).create_backup_job(self.account)
                self.assertTrue(refused.is_err())
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(status="failed")

    def test_a_definite_chain_failure_does_not_hold_the_account(self) -> None:
        job = self.admit_and_run("base", Err("node refused", retriability=Retriability.NOT_RETRIABLE))
        self.assertEqual(job.status, "failed")
        self.assertFalse(account_has_active_operation(self.account))

    def test_an_uncertain_standalone_backup_still_just_fails(self) -> None:
        job = self.admit_and_run("standalone", Err("lost response", retriability=Retriability.UNKNOWN))
        self.assertEqual(job.status, "failed")

    def test_a_dead_chain_worker_is_reclaimed_into_attention(self) -> None:
        cases = {"base": "attention", "differential": "attention", "standalone": "failed"}
        for role, expected in cases.items():
            with self.subTest(role=role):
                job = VirtualminProvisioningJob.objects.create(
                    operation="backup_domain",
                    account=self.account,
                    server=self.server,
                    status="pending",
                    parameters={"task_budget_seconds": 600, "chain_role": role},
                )
                VirtualminProvisioningJob.claim_execution(job.pk, uuid.uuid4(), timezone.now())
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
                    execution_deadline=timezone.now() - timedelta(seconds=600)
                )
                counts = {"jobs_dispatch_lost": 0, "jobs_taken_over": 0}
                virtualmin_tasks._reclaim_backup_restore_jobs(counts)
                job.refresh_from_db()
                self.assertEqual(job.status, expected)
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(status="completed")


class ConfirmStoppedTests(ChainFixtures, ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.staff = User.objects.create_user(
            email="chain-resolver@example.com", password="resolver-test-password", staff_role="admin"
        )
        self.client.force_login(self.staff)
        self.base = self.live_chain(self.account, epoch=2)
        self.token = str(uuid.uuid4())
        self.job = VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            status="attention",
            parameters={
                "chain_role": "differential",
                "chain_token": self.token,
                "chain_epoch": 2,
                "virtualmin_domain_id": DOMAIN_ID,
            },
            result={"retriability": "unknown"},
        )
        self.url = reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk])
        self.calls: list[dict[str, Any]] = []

    def resolve(self, step: Any) -> None:
        def run(service: VirtualminBackupService, variables: dict[str, Any], **kwargs: Any) -> Any:
            # What the account looks like at the moment the marker is written.
            self.account.refresh_from_db()
            self.job.refresh_from_db()
            self.calls.append(
                {
                    "variables": variables,
                    "kwargs": kwargs,
                    "job_status": self.job.status,
                    "chain_epoch": self.account.chain_epoch,
                }
            )
            return step

        with patch.object(VirtualminBackupService, "run_chain_step", autospec=True, side_effect=run):
            response = self.client.post(self.url, {"note": "node checked"})
        self.assertEqual(response.status_code, 302)
        self.job.refresh_from_db()
        self.account.refresh_from_db()

    def test_the_marker_is_written_then_the_chain_is_cleared_then_the_account_is_released(self) -> None:
        self.resolve(Ok(cancel_result()))
        (call,) = self.calls
        self.assertEqual(
            {k: call["variables"][k] for k in ("chain_action", "chain_domain_id", "chain_token")},
            {"chain_action": "cancel", "chain_domain_id": DOMAIN_ID, "chain_token": self.token},
        )
        self.assertEqual((call["job_status"], call["chain_epoch"]), ("attention", 2), "marker comes first")
        self.assertEqual(self.job.status, "failed")
        self.assertIn("chain-resolver@example.com", self.job.status_message)
        self.assertEqual((self.account.chain_base, self.account.chain_epoch), (None, 3))
        self.assertFalse(account_has_active_operation(self.account))

    def test_nothing_is_released_when_the_marker_cannot_be_written(self) -> None:
        refusals = {
            "lock held": Ok(cancel_result(outcome="refused", reason="lock_busy")),
            "node unreachable": Err("Chain step playbook failed", retriability=Retriability.UNKNOWN),
        }
        for label, step in refusals.items():
            with self.subTest(case=label):
                self.resolve(step)
                self.assertEqual(self.job.status, "attention")
                self.assertEqual((self.account.chain_base_id, self.account.chain_epoch), (self.base.pk, 2))
                self.assertTrue(account_has_active_operation(self.account))

    def test_a_job_that_never_recorded_a_domain_id_never_dispatched_a_step(self) -> None:
        params = {k: v for k, v in self.job.parameters.items() if k != "virtualmin_domain_id"}
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(parameters=params)
        self.resolve(Err("must not be called"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.job.status, "failed")
        self.assertEqual(self.account.chain_epoch, 3)

    def test_a_job_whose_step_already_concluded_needs_no_marker(self) -> None:
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(
            result={"backup_id": "d-1", "fp_before": SNAP_A, "fp_after": SNAP_A}
        )
        self.resolve(Err("must not be called"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.job.status, "failed")

    def test_a_job_that_is_no_longer_in_attention_changes_nothing(self) -> None:
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(status="completed")
        self.resolve(Ok(cancel_result()))
        self.assertEqual(self.job.status, "completed")
        self.assertEqual(self.account.chain_epoch, 2)

    def test_restore_jobs_resolve_as_before_without_a_marker(self) -> None:
        restore = VirtualminProvisioningJob.objects.create(
            operation="restore_domain", account=self.account, server=self.server, status="attention"
        )
        with patch.object(VirtualminBackupService, "run_chain_step") as step:
            self.client.post(reverse("provisioning:virtualmin_job_resolve", args=[restore.pk]), {"note": "ok"})
        step.assert_not_called()
        restore.refresh_from_db()
        self.assertEqual(restore.status, "failed")

    def test_the_cancel_playbook_input_is_what_the_node_script_validates(self) -> None:
        # The variables the resolver sends must satisfy the playbook's own input assertions.
        self.resolve(Ok(cancel_result()))
        variables = self.calls[0]["variables"]
        self.assertRegex(variables["chain_domain"], r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
        self.assertRegex(variables["chain_token"], r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        self.assertEqual(self.calls[0]["kwargs"], {"token": self.token, "mode": "cancel", "domain_id": DOMAIN_ID})
