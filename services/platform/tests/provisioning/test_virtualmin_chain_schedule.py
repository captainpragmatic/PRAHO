"""The hourly chain-backup schedule: who is due, what is taken, and what happens when it fails.

The scheduler decides from the account's chain state, never from error text: an account with a live
base gets a differential, one without gets a base. Evidence from the node that ends the chain (the
snapshot is absent or different) therefore turns the next run into a base, while a failure that
leaves the chain alone (the node is busy, a metadata read failed) backs off and retries the same
role, and raises one alert after several in a row. It only creates what staff could create:
it goes through the same admission, so every exclusion applies.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.utils import timezone
from django_q.models import Schedule

from apps.audit.models import AuditEvent
from apps.common.types import Err, Retriability
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import ChainStepResult, VirtualminBackupService
from apps.provisioning.virtualmin_chain_schedule import (
    ALERT_AFTER_FAILURES,
    SCHEDULER_ACTOR,
    backoff_for,
    base_interval,
    differential_interval,
    run_chain_backup_sweep,
)
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.settings.services import SettingsService
from tests.helpers.fsm_helpers import force_status
from tests.helpers.legacy_settings import store_legacy_integer
from tests.provisioning.test_virtualmin_account_exclusion import ExclusionCase
from tests.provisioning.test_virtualmin_chain_interruption import DOMAIN_ID
from tests.provisioning.test_virtualmin_chain_playbook import SNAP_A
from tests.provisioning.test_virtualmin_chain_state import ChainFixtures

BASE_KEY = "provisioning.chain_base_interval_days"
DIFFERENTIAL_KEY = "provisioning.chain_differential_interval_hours"
HOUR = timedelta(hours=1)


class ScheduleCase(ChainFixtures, ExclusionCase):
    """An eligible account on a managed node, a clock the tests move, and a sweep that queues nothing real."""

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.account = self._account()
        self.deployment()
        self.enable_incremental_backups()
        self.now = timezone.now()

    def sweep(self, ahead: timedelta = timedelta(0)) -> dict[str, Any]:
        with patch("django_q.tasks.async_task"):
            return run_chain_backup_sweep(now=self.now + ahead)

    def chain_jobs(self) -> list[VirtualminProvisioningJob]:
        return list(
            VirtualminProvisioningJob.objects.filter(
                operation="backup_domain", parameters__chain_role__in=("base", "differential")
            ).order_by("created_at")
        )

    def live_base(self, age: timedelta, *, epoch: int = 2) -> VirtualminProvisioningJob:
        base = self.live_chain(self.account, epoch=epoch)
        VirtualminProvisioningJob.objects.filter(pk=base.pk).update(
            completed_at=self.now - age, parameters={"chain_role": "base", "chain_epoch": epoch}
        )
        base.refresh_from_db()
        return base

    def differential_of(self, base: VirtualminProvisioningJob, age: timedelta) -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            status="completed",
            completed_at=self.now - age,
            parameters={"chain_role": "differential", "chain_epoch": 2, "base_job_id": str(base.pk)},
            result={"backup_id": "diff-1", "fp_before": SNAP_A, "fp_after": SNAP_A},
        )

    def roles(self, outcome: dict[str, Any]) -> list[str]:
        return [admitted["role"] for admitted in outcome["admitted"]]

    def _service_for(self, index: int) -> Any:
        from apps.provisioning.models import Service  # noqa: PLC0415

        return Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=f"bulk{index}.example.com",
            domain=f"bulk{index}.example.com",
            username=f"bulk{index}",
            price=self.service.price,
            status="active",
        )


class IntervalSettingTests(ScheduleCase):
    def test_the_defaults_are_seven_days_and_twenty_four_hours(self) -> None:
        self.assertEqual(base_interval(), timedelta(days=7))
        self.assertEqual(differential_interval(), timedelta(hours=24))

    def test_a_change_moves_what_is_due(self) -> None:
        self.live_base(timedelta(hours=30))
        self.assertEqual(self.roles(self.sweep()), ["differential"])
        VirtualminProvisioningJob.objects.filter(status="pending").update(status="completed")

        self.assertTrue(SettingsService.update_setting("provisioning.chain_differential_interval_hours", 48).is_ok())
        self.assertEqual(differential_interval(), timedelta(hours=48))
        self.assertEqual(self.roles(self.sweep()), [], "30 hours is inside a 48 hour interval")

        self.assertTrue(SettingsService.update_setting("provisioning.chain_base_interval_days", 1).is_ok())
        self.assertEqual(base_interval(), timedelta(days=1))
        self.assertEqual(self.roles(self.sweep()), ["base"], "30 hours is past a one day base interval")

    def test_zero_and_negative_values_are_refused_where_settings_are_written(self) -> None:
        for key in (BASE_KEY, DIFFERENTIAL_KEY):
            for value in (0, -1):
                with self.subTest(key=key, value=value):
                    self.assertTrue(SettingsService.update_setting(key, value).is_err())

    def test_a_legacy_nonpositive_value_falls_back_to_the_default(self) -> None:
        for key, read, default in (
            (BASE_KEY, base_interval, timedelta(days=7)),
            (DIFFERENTIAL_KEY, differential_interval, timedelta(hours=24)),
        ):
            for stored in (0, -3):
                with self.subTest(key=key, stored=stored):
                    store_legacy_integer(key, stored)
                    cache.clear()
                    self.assertEqual(read(), default)


class DueSelectionTests(ScheduleCase):
    def test_an_account_without_a_live_base_gets_a_base(self) -> None:
        outcome = self.sweep()
        self.assertEqual(self.roles(outcome), ["base"])
        (job,) = self.chain_jobs()
        self.assertEqual(job.parameters["chain_role"], "base")
        self.assertEqual(job.parameters["initiated_by"], SCHEDULER_ACTOR)
        self.assertEqual(job.status, "pending")

    def test_a_fresh_chain_is_left_alone(self) -> None:
        base = self.live_base(timedelta(hours=2))
        self.differential_of(base, timedelta(minutes=30))
        outcome = self.sweep()
        self.assertEqual(self.roles(outcome), [])
        self.assertEqual(outcome["skipped"].get("not_due"), 1)
        self.assertEqual(self.chain_jobs()[0].pk, base.pk)
        self.assertEqual(len(self.chain_jobs()), 2, "no job was added")

    def test_the_differential_interval_is_inclusive_at_its_boundary(self) -> None:
        base = self.live_base(timedelta(days=2))
        self.differential_of(base, timedelta(hours=24) - timedelta(seconds=1))
        self.assertEqual(self.roles(self.sweep()), [])
        VirtualminProvisioningJob.objects.filter(parameters__chain_role="differential").update(
            completed_at=self.now - timedelta(hours=24)
        )
        self.assertEqual(self.roles(self.sweep()), ["differential"])

    def test_a_base_with_no_differential_is_extended_once_the_interval_passes_since_the_base(self) -> None:
        self.live_base(timedelta(hours=23))
        self.assertEqual(self.roles(self.sweep()), [])
        self.assertEqual(self.roles(self.sweep(ahead=2 * HOUR)), ["differential"])

    def test_the_base_interval_wins_over_a_fresh_differential(self) -> None:
        base = self.live_base(timedelta(days=7))
        self.differential_of(base, timedelta(hours=1))
        self.assertEqual(self.roles(self.sweep()), ["base"])

    def test_the_base_interval_is_inclusive_at_its_boundary(self) -> None:
        base = self.live_base(timedelta(days=7) - timedelta(seconds=1))
        self.differential_of(base, timedelta(hours=1))
        self.assertEqual(self.roles(self.sweep()), [])

    def test_a_differential_of_an_earlier_base_does_not_count_for_this_chain(self) -> None:
        self.live_base(timedelta(hours=30))
        VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            status="completed",
            completed_at=self.now - HOUR,
            parameters={"chain_role": "differential", "chain_epoch": 1, "base_job_id": "an-older-base"},
        )
        self.assertEqual(self.roles(self.sweep()), ["differential"])

    def test_one_sweep_takes_one_job_per_account_and_never_a_second_while_it_is_pending(self) -> None:
        self.assertEqual(self.roles(self.sweep()), ["base"])
        again = self.sweep()
        self.assertEqual(self.roles(again), [])
        self.assertEqual(again["skipped"].get("excluded"), 1)
        self.assertEqual(len(self.chain_jobs()), 1)

    def test_a_sweep_admits_a_bounded_number_of_jobs_and_the_rest_wait_for_the_next(self) -> None:
        from apps.provisioning.virtualmin_chain_schedule import MAX_ADMISSIONS_PER_SWEEP  # noqa: PLC0415

        for index in range(MAX_ADMISSIONS_PER_SWEEP + 2):
            other = VirtualminAccount.objects.create(
                service=self._service_for(index),
                server=self.server,
                domain=f"bulk{index}.example.com",
                virtualmin_username=f"bulk{index}",
                status="active",
                praho_customer_id=self.customer.pk,
            )
            self.assertIsNotNone(other.pk)
        first = self.sweep()
        self.assertEqual(len(first["admitted"]), MAX_ADMISSIONS_PER_SWEEP)
        second = self.sweep()
        self.assertEqual(len(second["admitted"]), 3, "the account left over plus the two that did not fit")
        self.assertEqual(len({job.account_id for job in self.chain_jobs()}), MAX_ADMISSIONS_PER_SWEEP + 3)


class FlagAndEligibilityTests(ScheduleCase):
    def assert_nothing_taken(self, outcome: dict[str, Any], reason: str) -> None:
        self.assertEqual(self.roles(outcome), [])
        self.assertEqual(outcome["skipped"].get(reason), 1, outcome)
        self.assertEqual(self.chain_jobs(), [])

    def test_with_the_flag_off_nothing_is_scheduled(self) -> None:
        self.assertTrue(SettingsService.update_setting("provisioning.incremental_backups_enabled", False).is_ok())
        with patch("django_q.tasks.async_task") as queued:
            outcome = run_chain_backup_sweep(now=self.now)
        self.assertFalse(outcome["enabled"])
        self.assertEqual(outcome["admitted"], [])
        queued.assert_not_called()
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_turning_the_flag_off_leaves_existing_chains_alone(self) -> None:
        base = self.live_base(timedelta(days=30))
        self.assertTrue(SettingsService.update_setting("provisioning.incremental_backups_enabled", False).is_ok())
        self.sweep()
        self.account.refresh_from_db()
        self.assertEqual(self.account.chain_base_id, base.pk)

    def test_an_account_with_another_operation_is_skipped_not_failed(self) -> None:
        for operation, status in (
            ("backup_domain", "running"),
            ("backup_domain", "attention"),
            ("restore_domain", "pending"),
            ("delete_domain", "pending"),
        ):
            with self.subTest(operation=operation, status=status):
                held = self._job(self.account, operation, status)
                self.assert_nothing_taken(self.sweep(), "excluded")
                VirtualminProvisioningJob.objects.filter(pk=held.pk).update(status="failed")

    def test_an_account_being_migrated_is_skipped(self) -> None:
        VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self._other_server(), status="restoring"
        )
        self.assert_nothing_taken(self.sweep(), "excluded")

    def test_a_suspended_account_is_skipped(self) -> None:
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="suspended")
        outcome = self.sweep()  # not even looked at: the sweep selects active accounts only
        self.assertEqual(self.roles(outcome), [])
        self.assertEqual(self.chain_jobs(), [])

    def test_an_account_of_a_suspended_service_is_skipped(self) -> None:
        for status in ("suspended", "terminated", "expired"):
            with self.subTest(status=status):
                force_status(self.service, status)
                self.assert_nothing_taken(self.sweep(), "ineligible")

    def test_a_node_that_is_not_serving_is_skipped(self) -> None:
        for fields in ({"status": "maintenance"}, {"status": "failed"}, {"status": "disabled"}, {"is_draining": True}):
            with self.subTest(**fields):
                VirtualminServer.objects.filter(pk=self.server.pk).update(**fields)
                outcome = self.sweep()
                self.assertEqual(self.roles(outcome), [])
                self.assertEqual(self.chain_jobs(), [])
                VirtualminServer.objects.filter(pk=self.server.pk).update(status="active", is_draining=False)

    def test_a_manually_registered_node_without_a_deployment_is_skipped_without_a_failure(self) -> None:
        from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415

        NodeDeployment.objects.all().delete()
        self.server.refresh_from_db()
        self.assert_nothing_taken(self.sweep(), "unmanaged_node")
        self.assertFalse(AuditEvent.objects.filter(action="virtualmin_chain_backup_alert").exists())

    def test_one_account_failing_to_be_considered_does_not_stop_the_others(self) -> None:
        from apps.provisioning import virtualmin_chain_schedule  # noqa: PLC0415

        real = virtualmin_chain_schedule.due_role

        def explode_for_the_first(account: VirtualminAccount, now: Any) -> Any:
            if account.pk == self.account.pk:
                raise RuntimeError("unreadable row")
            return real(account, now)

        other_service = self._service_for(900)
        VirtualminAccount.objects.create(
            service=other_service,
            server=self.server,
            domain="other-ok.example.com",
            virtualmin_username="otherok",
            status="active",
            praho_customer_id=self.customer.pk,
        )
        with patch.object(virtualmin_chain_schedule, "due_role", side_effect=explode_for_the_first):
            outcome = self.sweep()
        self.assertEqual(outcome["errors"], 1)
        self.assertEqual([admitted["domain"] for admitted in outcome["admitted"]], ["other-ok.example.com"])


class BaseInsteadOfDifferentialTests(ScheduleCase):
    """A differential whose base is gone, unusable or refused by the node becomes a base."""

    def refused(self, fp_before: str) -> ChainStepResult:
        return ChainStepResult(
            outcome="refused",
            reason="fingerprint_mismatch",
            ran=False,
            mode="differential",
            fp_before=fp_before,
            fp_after=fp_before,
            backup_rc=-1,
            sha256="",
            size=0,
            detail="",
            archive="",
        )

    def run_job(self, job: VirtualminProvisioningJob, step: Any) -> VirtualminProvisioningJob:
        from apps.common.types import Ok  # noqa: PLC0415

        with (
            patch.object(VirtualminBackupService, "_validate_backup_preconditions", return_value=Ok(None)),
            patch.object(VirtualminBackupService, "_domain_features", return_value=None),
            patch.object(VirtualminBackupService, "_read_domain_id", return_value=Ok(DOMAIN_ID)),
            patch.object(VirtualminBackupService, "run_chain_step", return_value=Ok(step)),
        ):
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        job.refresh_from_db()
        return job

    def test_a_missing_base_is_a_base_not_a_refused_differential(self) -> None:
        # The chain was invalidated (a restore, a migration): the due differential becomes a base.
        self.live_base(timedelta(hours=30))
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            chain_base=None, chain_base_fingerprint="", chain_epoch=3
        )
        outcome = self.sweep()
        self.assertEqual(self.roles(outcome), ["base"])
        self.assertEqual(outcome["admitted"][0]["reason"], "no_live_base")

    def test_a_base_that_left_no_usable_evidence_is_replaced_by_a_new_base(self) -> None:
        base = self.live_base(timedelta(hours=30))
        VirtualminProvisioningJob.objects.filter(pk=base.pk).update(result={})
        outcome = self.sweep()
        self.assertEqual(self.roles(outcome), ["base"])
        self.assertEqual(outcome["admitted"][0]["reason"], "base_evidence_unusable")

    def test_a_snapshot_the_node_no_longer_has_leads_to_a_base_on_the_next_sweep_without_waiting(self) -> None:
        for seen in ("ABSENT", "f" * 64 + ":9"):
            with self.subTest(snapshot=seen):
                self.live_base(timedelta(hours=30))
                (differential_job,) = [
                    VirtualminProvisioningJob.objects.get(pk=admitted["job_id"])
                    for admitted in self.sweep()["admitted"]
                ]
                self.assertEqual(differential_job.parameters["chain_role"], "differential")

                done = self.run_job(differential_job, self.refused(seen))
                self.assertEqual(done.status, "failed")
                self.account.refresh_from_db()
                self.assertIsNone(self.account.chain_base, "the node's evidence ended the chain")

                later = self.sweep(ahead=timedelta(minutes=1))
                self.assertEqual(self.roles(later), ["base"], "taken at once: this is not an operational failure")
                VirtualminProvisioningJob.objects.all().delete()

    def test_a_failure_that_leaves_the_chain_alone_never_turns_into_a_base(self) -> None:
        base = self.live_base(timedelta(hours=30))
        (admitted,) = self.sweep()["admitted"]
        job = VirtualminProvisioningJob.objects.get(pk=admitted["job_id"])
        with patch.object(
            VirtualminBackupService,
            "backup_domain",
            autospec=True,
            return_value=Err("could not read the domain id", retriability=Retriability.RETRIABLE),
        ):
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        job.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.result["chain_state"], "intact")
        self.assertEqual(self.account.chain_base_id, base.pk)
        for minutes in (5, 29):
            outcome = self.sweep(ahead=timedelta(minutes=minutes))
            self.assertEqual(self.roles(outcome), [], "still inside the backoff window")
            self.assertEqual(outcome["skipped"].get("backoff"), 1)
        retried = self.sweep(ahead=timedelta(minutes=31))
        self.assertEqual(self.roles(retried), ["differential"], "the same role again, not a base")


class OperationalFailureBackoffTests(ScheduleCase):
    """Operational failures back off with growing delay, raise one alert at N, and reset on success."""

    STEP = timedelta(hours=25)  # past every backoff and past the differential interval

    def setUp(self) -> None:
        super().setUp()
        self.base = self.live_base(timedelta(hours=30))
        self.clock = timedelta(0)

    def admit_at(self, ahead: timedelta) -> VirtualminProvisioningJob:
        (admitted,) = self.sweep(ahead=ahead)["admitted"]
        return VirtualminProvisioningJob.objects.get(pk=admitted["job_id"])

    def fail(self, job: VirtualminProvisioningJob, at: timedelta, *, error: Any = None) -> VirtualminProvisioningJob:
        failure = error or Err("node busy", retriability=Retriability.RETRIABLE)
        with patch.object(VirtualminBackupService, "backup_domain", autospec=True, return_value=failure):
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(completed_at=self.now + at)
        job.refresh_from_db()
        return job

    def fail_next(self, *, error: Any = None) -> VirtualminProvisioningJob:
        self.clock += self.STEP
        return self.fail(self.admit_at(self.clock), self.clock, error=error)

    def alerts(self) -> list[AuditEvent]:
        return list(AuditEvent.objects.filter(action="virtualmin_chain_backup_alert"))

    def test_the_delay_doubles_and_is_capped(self) -> None:
        delays = [backoff_for(streak) for streak in range(1, 9)]
        self.assertEqual(delays[:4], [timedelta(minutes=30), HOUR, 2 * HOUR, 4 * HOUR])
        self.assertEqual(delays[-1], timedelta(hours=24))
        self.assertEqual(delays, sorted(delays))

    def test_each_consecutive_failure_lengthens_the_wait(self) -> None:
        self.fail_next()
        first_failure = self.clock
        self.assertEqual(self.roles(self.sweep(ahead=first_failure + timedelta(minutes=29))), [])
        second = self.admit_at(first_failure + timedelta(minutes=31))
        second_failure = first_failure + timedelta(minutes=31)
        self.fail(second, second_failure)
        self.assertEqual(self.roles(self.sweep(ahead=second_failure + timedelta(minutes=59))), [])
        self.assertEqual(self.roles(self.sweep(ahead=second_failure + timedelta(minutes=61))), ["differential"])

    def test_exactly_one_alert_is_raised_when_the_streak_reaches_the_threshold(self) -> None:
        for _ in range(ALERT_AFTER_FAILURES - 1):
            self.fail_next()
        self.assertEqual(self.alerts(), [])
        self.fail_next()
        (alert,) = self.alerts()
        self.assertIn(self.account.domain, alert.description)
        self.assertTrue(alert.requires_review)
        self.assertEqual(alert.severity, "high")
        self.fail_next()
        self.assertEqual(len(self.alerts()), 1, "the next failure belongs to the same streak")

    def test_a_success_resets_the_streak(self) -> None:
        for _ in range(ALERT_AFTER_FAILURES - 1):
            self.fail_next()
        VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            status="completed",
            completed_at=self.now + self.clock + timedelta(minutes=30),
            parameters={"chain_role": "differential", "chain_epoch": 2, "base_job_id": str(self.base.pk)},
        )
        for _ in range(ALERT_AFTER_FAILURES - 1):
            self.fail_next()
        self.assertEqual(self.alerts(), [], "two failures, a success and two more are not a streak of three")

    def test_jobs_that_ended_the_chain_or_were_resolved_by_an_operator_do_not_count(self) -> None:
        for chain_state in ("moved", None):
            for _ in range(ALERT_AFTER_FAILURES):
                VirtualminProvisioningJob.objects.create(
                    operation="backup_domain",
                    account=self.account,
                    server=self.server,
                    status="failed",
                    completed_at=self.now - HOUR,
                    parameters={"chain_role": "differential", "chain_epoch": 2, "base_job_id": str(self.base.pk)},
                    result={"chain_state": chain_state} if chain_state else {},
                )
        self.assertEqual(self.roles(self.sweep()), ["differential"], "no backoff from those")

    def test_an_uncertain_job_holds_the_account_and_is_not_counted_as_a_failure(self) -> None:
        job = self.fail_next(error=Err("playbook timed out", retriability=Retriability.UNKNOWN))
        self.assertEqual(job.status, "attention")
        self.assertEqual(self.alerts(), [])
        outcome = self.sweep(ahead=self.clock + timedelta(days=3))
        self.assertEqual(self.roles(outcome), [])
        self.assertEqual(outcome["skipped"].get("excluded"), 1)


class ScheduleRegistrationTests(ScheduleCase):
    def test_the_task_is_registered_hourly_and_setup_is_idempotent(self) -> None:
        first = virtualmin_tasks.setup_virtualmin_scheduled_tasks()
        second = virtualmin_tasks.setup_virtualmin_scheduled_tasks()
        self.assertEqual(first["chain_backups"], "created")
        self.assertEqual(second["chain_backups"], "updated")
        row = Schedule.objects.get(name="virtualmin-chain-backups")
        self.assertEqual(row.func, "apps.provisioning.virtualmin_tasks.schedule_virtualmin_chain_backups")
        self.assertEqual((row.schedule_type, row.minutes), ("I", 60))
        self.assertEqual(Schedule.objects.filter(name="virtualmin-chain-backups").count(), 1)

    def test_setup_repairs_a_drifted_row(self) -> None:
        Schedule.objects.create(
            name="virtualmin-chain-backups", func="somewhere.else", schedule_type="D", cluster="praho-cluster"
        )
        virtualmin_tasks.setup_virtualmin_scheduled_tasks()
        row = Schedule.objects.get(name="virtualmin-chain-backups")
        self.assertEqual(
            (row.func, row.schedule_type, row.minutes),
            ("apps.provisioning.virtualmin_tasks.schedule_virtualmin_chain_backups", "I", 60),
        )

    def test_the_task_wrapper_runs_the_sweep(self) -> None:
        with patch("django_q.tasks.async_task"):
            outcome = virtualmin_tasks.schedule_virtualmin_chain_backups()
        self.assertTrue(outcome["success"])
        self.assertEqual([admitted["role"] for admitted in outcome["admitted"]], ["base"])
