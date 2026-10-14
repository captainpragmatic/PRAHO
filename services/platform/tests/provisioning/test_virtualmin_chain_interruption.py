"""Chain jobs that may still be running on the node keep the account until an operator confirms.

A timeout, an ambiguous playbook error or a dead worker says nothing about whether the node
step finished, is waiting for the lock, or will start later. Those jobs go to attention and
keep the exclusion. "Confirm stopped" writes the job's cancel marker on the node under the
lock, invalidates the chain, and only then releases the exclusion.
"""

from __future__ import annotations

import uuid
from contextlib import ExitStack
from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.common.types import Err, Ok, Retriability
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import ChainStepResult, VirtualminBackupService
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
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

    def test_a_job_without_a_domain_id_has_nothing_to_cancel_on_the_node(self) -> None:
        # Dispatch refuses a step whose domain id (and archive name) were not durably recorded
        # (MissedNoteTests), so a job in attention without one never started a node step.
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


class ChainRunnerCase(ChainFixtures, ExclusionCase):
    """Admits real chain jobs for an account, to be run through the real runner and service."""

    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.enable_incremental_backups()

    def admit(self, role: str = "base") -> VirtualminProvisioningJob:
        from apps.provisioning.virtualmin_backup_service import BackupConfig  # noqa: PLC0415

        if role == "differential":
            self.live_chain(self.account, epoch=2)
        with patch("django_q.tasks.async_task"):
            return VirtualminBackupManagementService(self.server).create_backup_job(
                self.account, BackupConfig(chain_role=role)
            ).unwrap()


class MissedNoteTests(ChainRunnerCase):
    """A step is dispatched only when the evidence a cancel needs is durable and the job is still ours."""

    def run_job(self, job: VirtualminProvisioningJob, *, during_domain_id_read: Any = None) -> Any:
        """Run the job through the real runner and service, with only the node and the listing faked."""

        def read_domain_id(service: VirtualminBackupService, account: Any) -> Any:
            if during_domain_id_read is not None:
                during_domain_id_read()
            return Ok(DOMAIN_ID)

        with (
            patch.object(VirtualminBackupService, "_validate_backup_preconditions", return_value=Ok(None)),
            patch.object(VirtualminBackupService, "_domain_features", return_value=None),
            patch.object(VirtualminBackupService, "_read_domain_id", autospec=True, side_effect=read_domain_id),
            patch.object(VirtualminBackupService, "run_chain_step", autospec=True) as step,
        ):
            outcome = virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        self.step = step
        job.refresh_from_db()
        return outcome

    def test_a_takeover_between_the_domain_id_read_and_the_note_dispatches_nothing(self) -> None:
        for role in ("base", "differential"):
            with self.subTest(role=role):
                job = self.admit(role)

                def take_over(job: VirtualminProvisioningJob = job) -> None:
                    VirtualminProvisioningJob.take_over_execution(job.pk, "attention", "Worker interrupted")

                self.run_job(job, during_domain_id_read=take_over)
                self.step.assert_not_called()
                self.assertNotIn("virtualmin_domain_id", job.parameters)
                self.assertEqual(job.status, "attention")
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(status="failed")

    def test_a_deadline_that_passes_after_the_note_dispatches_nothing(self) -> None:
        job = self.admit("base")

        def expire() -> None:
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
                execution_deadline=timezone.now() - timedelta(seconds=1)
            )

        self.run_job(job, during_domain_id_read=expire)
        self.step.assert_not_called()
        self.assertEqual(job.parameters["virtualmin_domain_id"], DOMAIN_ID, "the note was written before the expiry")

    def test_a_job_that_keeps_its_token_dispatches_the_step_after_recording_it(self) -> None:
        job = self.admit("base")
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update()  # no interference
        self.step_calls: list[str] = []

        def fail_step(*args: Any, **kwargs: Any) -> Any:
            row = VirtualminProvisioningJob.objects.get(pk=job.pk)
            self.step_calls.append(str(row.parameters.get("virtualmin_domain_id")))
            return Err("node refused", retriability=Retriability.NOT_RETRIABLE)

        with (
            patch.object(VirtualminBackupService, "_validate_backup_preconditions", return_value=Ok(None)),
            patch.object(VirtualminBackupService, "_domain_features", return_value=None),
            patch.object(VirtualminBackupService, "_read_domain_id", return_value=Ok(DOMAIN_ID)),
            patch.object(VirtualminBackupService, "run_chain_step", autospec=True, side_effect=fail_step),
        ):
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        self.assertEqual(self.step_calls, [DOMAIN_ID], "the id is durable before the step runs")


class NodeLostTests(ChainFixtures, ExclusionCase):
    """A chain job on a node that is gone is released without the node, but only when the node is gone."""

    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.staff = User.objects.create_user(
            email="node-lost@example.com", password="node-lost-test-password", staff_role="admin"
        )
        self.client.force_login(self.staff)
        self.base = self.live_chain(self.account, epoch=2)
        self.token = uuid.uuid4()
        self.job = VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            status="attention",
            execution_token=self.token,
            parameters={
                "chain_role": "differential",
                "chain_token": str(uuid.uuid4()),
                "chain_epoch": 2,
                "virtualmin_domain_id": DOMAIN_ID,
            },
        )
        self.url = reverse("provisioning:virtualmin_job_node_lost", args=[self.job.pk])

    def declare_lost(self) -> Any:
        with patch.object(VirtualminBackupService, "run_chain_step") as node:
            response = self.client.post(self.url, {"note": "datacentre fire"})
        node.assert_not_called()
        self.job.refresh_from_db()
        self.account.refresh_from_db()
        return response

    def deployment(self, status: str) -> None:
        from apps.infrastructure.models import (  # noqa: PLC0415
            CloudProvider,
            NodeDeployment,
            NodeRegion,
            NodeSize,
            PanelType,
        )

        provider = CloudProvider.objects.create(
            name="Lost provider", provider_type="hetzner", code="lst", credential_identifier="lost-test"
        )
        NodeDeployment.objects.create(
            provider=provider,
            node_size=NodeSize.objects.create(
                provider=provider,
                name="Lost small",
                display_name="Small",
                provider_type_id="cpx21",
                vcpus=2,
                memory_gb=4,
                disk_gb=40,
                hourly_cost_eur="0.01",
                monthly_cost_eur="5.00",
            ),
            region=NodeRegion.objects.create(
                provider=provider,
                name="Falkenstein",
                provider_region_id="fsn1",
                normalized_code="fsn1",
                country_code="de",
                city="Falkenstein",
            ),
            panel_type=PanelType.objects.create(
                name="Lost Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
            ),
            hostname="prd-lst-het-de-fsn1-001",
            node_number=1,
            ipv4_address="203.0.113.77",
            virtualmin_server=self.server,
            status=status,
        )
        self.server.refresh_from_db()

    def test_a_node_that_is_still_usable_cannot_be_declared_lost(self) -> None:
        for server_status in ("active", "maintenance", "disabled"):
            with self.subTest(server_status=server_status):
                VirtualminServer.objects.filter(pk=self.server.pk).update(status=server_status)
                response = self.declare_lost()
                self.assertEqual(response.status_code, 302)
                self.assertEqual(self.job.status, "attention")
                self.assertEqual(self.job.execution_token, self.token)
                self.assertEqual((self.account.chain_base_id, self.account.chain_epoch), (self.base.pk, 2))
                self.assertTrue(account_has_active_operation(self.account))

    def test_a_failed_server_releases_the_job_rotates_its_token_and_clears_the_chain(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        self.declare_lost()
        self.assertEqual(self.job.status, "failed")
        self.assertIn("Node lost", self.job.status_message)
        self.assertIn("node-lost@example.com", self.job.status_message)
        self.assertNotEqual(self.job.execution_token, self.token)
        self.assertEqual((self.account.chain_base, self.account.chain_epoch), (None, 3))
        self.assertFalse(account_has_active_operation(self.account))

    def test_a_destroyed_deployment_counts_as_decommissioned(self) -> None:
        from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415

        self.deployment("completed")
        for status, allowed in (("completed", False), ("destroying", True), ("destroyed", True)):
            with self.subTest(deployment=status):
                NodeDeployment.objects.update(status=status)
                self.server.refresh_from_db()
                self.declare_lost()
                self.assertEqual(self.job.status, "failed" if allowed else "attention")
                VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(status="attention")

    def test_a_late_runner_of_a_lost_job_can_neither_publish_nor_link(self) -> None:
        from apps.provisioning.virtualmin_chain import complete_chain_job  # noqa: PLC0415

        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        self.declare_lost()
        self.assertFalse(VirtualminProvisioningJob.owns_execution(self.job.pk, self.token))
        outcome = complete_chain_job(self.job, self.token, {"backup_id": "late", "fp_before": "", "fp_after": SNAP_A})
        self.assertEqual(outcome, "superseded")
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "failed")
        self.assertEqual(VirtualminProvisioningJob.finish_execution(self.job.pk, self.token, "completed", ""), 0)

    def test_only_chain_jobs_in_attention_can_be_resolved_this_way(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        restore = VirtualminProvisioningJob.objects.create(
            operation="restore_domain", account=self.account, server=self.server, status="attention"
        )
        self.client.post(reverse("provisioning:virtualmin_job_node_lost", args=[restore.pk]))
        restore.refresh_from_db()
        self.assertEqual(restore.status, "attention")
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(status="completed")
        self.declare_lost()
        self.assertEqual(self.job.status, "completed")
        self.assertEqual(self.account.chain_epoch, 2, "a refused resolution must not touch the chain")

    def test_the_status_page_offers_node_lost_only_when_it_is_allowed(self) -> None:
        page = reverse("provisioning:virtualmin_job_status", args=[self.job.pk])
        before = self.client.get(page).content.decode()
        self.assertIn(reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk]), before)
        self.assertNotIn(self.url, before)
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        after = self.client.get(page).content.decode()
        self.assertIn(self.url, after)
        self.assertEqual(after.count("hx-confirm="), 2, "both resolutions ask for confirmation")


class SettledStepErrorTests(ChainRunnerCase):
    """UNKNOWN parks a chain job only while a dispatched node step is itself uncertain.

    A bare error before dispatch, or a failed fetch after the step reported its fingerprints, says
    nothing about the node step, so the job fails and releases the account instead of holding it.
    """

    def run_with(self, job: VirtualminProvisioningJob, **overrides: dict[str, Any]) -> None:
        """Run the real runner and service; ``overrides`` replace the default fakes by method name."""
        fakes: dict[str, dict[str, Any]] = {
            "_validate_backup_preconditions": {"return_value": Ok(None)},
            "_domain_features": {"return_value": None},
            "_read_domain_id": {"return_value": Ok(DOMAIN_ID)},
            **overrides,
        }
        with ExitStack() as contexts:
            for name, options in fakes.items():
                contexts.enter_context(patch.object(VirtualminBackupService, name, **options))
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        job.refresh_from_db()

    def test_a_fetch_failure_after_a_settled_step_fails_the_job_and_releases_the_account(self) -> None:
        job = self.admit("base")
        settled = Ok(
            ChainStepResult(
                outcome="ok",
                reason="completed",
                ran=True,
                mode="base",
                fp_before="ABSENT",
                fp_after=SNAP_A,
                backup_rc=0,
                sha256="d" * 64,
                size=10,
                detail="",
                archive="x",
            )
        )
        self.run_with(
            job,
            run_chain_step={"return_value": settled},
            _fetch_archive_to_spool={"return_value": Err("fetch lost", retriability=Retriability.UNKNOWN)},
        )
        self.assertEqual(job.status, "failed")
        self.assertFalse(account_has_active_operation(self.account))

    def test_a_bare_error_before_dispatch_fails_the_job_and_releases_the_account(self) -> None:
        for role in ("base", "differential"):
            with self.subTest(role=role):
                job = self.admit(role)
                self.run_with(job, _validate_backup_preconditions={"return_value": Err("not ready")})
                self.assertEqual(job.status, "failed")
                self.assertFalse(account_has_active_operation(self.account))

    def test_an_unknown_error_from_the_dispatched_step_still_parks_the_job(self) -> None:
        job = self.admit("base")
        self.run_with(job, run_chain_step={"return_value": Err("playbook timed out", retriability=Retriability.UNKNOWN)})
        self.assertEqual(job.status, "attention")
        self.assertTrue(account_has_active_operation(self.account))
