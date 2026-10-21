"""Migration states, their graph, and deferral (ADR-0061 P2.1, P2.2).

A transition outside the graph is refused (False, never an exception); a same-state write, terminal
included, is how a lease is released. Compensation is reachable only before the point of no return.
A step that must wait raises `MigrationDeferredError`: the row keeps its state, records `resume_after`,
and is woken by a ONCE schedule (the reclaim sweep is the fallback). A drain counts a migration once,
when the migration finishes, and a drain that waited on a deferred migration is woken by that finish.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from itertools import pairwise
from unittest.mock import Mock, patch
from uuid import uuid4

from django.utils import timezone
from django_q.models import Schedule

from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_drain_service import NodeDrainService
from apps.provisioning.virtualmin_migration_models import (
    PRE_COMMIT_STATUSES,
    NodeDrain,
    VirtualminMigration,
)
from apps.provisioning.virtualmin_migration_service import MigrationDeferredError, VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase

CUTOVER_PATH = (
    "pending",
    "lowering_ttl",
    "quiescing",
    "backing_up",
    "fetching",
    "pushing",
    "restoring",
    "verifying",
    "activating",
    "bridging",
    "repointing",
    "completed",
)


class StatesCase(MigrationTestBase):
    def _held(self, status: str, **fields: object) -> tuple[VirtualminMigration, object]:
        """The account's migration, in `status`, leased to the returned token."""
        migration = getattr(self, "_migration", None) or self._start()
        self._migration = migration
        token = uuid4()
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status=status, lease_token=token, worker_lease_expires_at=timezone.now() + timedelta(hours=1), **fields
        )
        migration.refresh_from_db()
        return migration, token


class TransitionGraphTests(StatesCase):
    def test_an_edge_outside_the_graph_is_refused_without_raising(self) -> None:
        migration, token = self._held("pending")

        self.assertFalse(migration.transition(token, "pending", "completed"))

        self.assertEqual(VirtualminMigration.objects.get(pk=migration.pk).status, "pending")

    def test_a_same_state_write_releases_a_lease_even_on_a_terminal_row(self) -> None:
        migration, token = self._held("completed")

        self.assertTrue(migration.transition(token, "completed", "completed", lease_token=None))

        self.assertIsNone(VirtualminMigration.objects.get(pk=migration.pk).lease_token)

    def test_a_terminal_row_never_moves(self) -> None:
        for terminal in ("completed", "failed", "rolled_back"):
            with self.subTest(terminal=terminal):
                migration, token = self._held(terminal)
                self.assertFalse(migration.transition(token, terminal, "needs_review"))

    def test_every_step_of_the_cutover_is_an_edge(self) -> None:
        for before, after in pairwise(CUTOVER_PATH):
            with self.subTest(edge=f"{before} -> {after}"):
                migration, token = self._held(before)
                self.assertTrue(migration.transition(token, before, after))

    def test_any_live_row_may_park_for_review(self) -> None:
        for status in CUTOVER_PATH[:-1]:
            with self.subTest(status=status):
                migration, token = self._held(status)
                self.assertTrue(migration.transition(token, status, "needs_review"))

    def test_compensation_is_reachable_only_before_the_point_of_no_return(self) -> None:
        for status in (*PRE_COMMIT_STATUSES, "needs_review"):
            with self.subTest(status=status):
                migration, token = self._held(status)
                self.assertTrue(migration.transition(token, status, "compensating"))
        for status in ("activating", "bridging", "repointing"):
            with self.subTest(status=status):
                migration, token = self._held(status)
                self.assertFalse(migration.transition(token, status, "compensating"))
        migration, token = self._held("needs_review", cutover_committed_at=timezone.now())
        self.assertFalse(migration.transition(token, "needs_review", "compensating"), "committed rows never compensate")

    def test_a_committed_row_no_longer_reserves_target_capacity(self) -> None:
        # The commit counts the domain on the target; the reservation must not count it again.
        migration, _ = self._held("bridging")
        self.assertEqual(VirtualminMigration.active_reservations(self.target), 1)

        VirtualminMigration.objects.filter(pk=migration.pk).update(cutover_committed_at=timezone.now())

        self.assertEqual(VirtualminMigration.active_reservations(self.target), 0)


class DeferralTests(StatesCase):
    def _defer(self, until: datetime, reason: str = "waiting for the old TTL") -> MigrationDeferredError:
        return MigrationDeferredError(until, reason)

    def test_a_step_that_must_wait_keeps_its_state_and_schedules_its_wake(self) -> None:
        migration = self._start()
        until = timezone.now() + timedelta(minutes=5)

        with (
            patch.object(VirtualminMigrationService, "_quiesce", side_effect=self._defer(until)),
            patch.object(virtualmin_tasks, "schedule") as schedule,
        ):
            result = virtualmin_tasks.run_virtualmin_migration(str(migration.pk))

        self.assertTrue(result["success"], result)
        migration.refresh_from_db()
        self.assertEqual((migration.status, migration.resume_after), ("quiescing", until))
        self.assertIsNone(migration.lease_token)
        schedule.assert_called_once_with(
            "apps.provisioning.virtualmin_tasks.run_virtualmin_migration",
            str(migration.pk),
            name=f"migration-wake-{migration.pk}-{int(until.timestamp())}",
            schedule_type=Schedule.ONCE,
            next_run=until,
        )

    def test_a_wake_that_cannot_be_scheduled_is_not_fatal(self) -> None:
        migration = self._start()
        until = timezone.now() + timedelta(minutes=5)

        with (
            patch.object(VirtualminMigrationService, "_quiesce", side_effect=self._defer(until)),
            patch.object(virtualmin_tasks, "schedule", side_effect=RuntimeError("broker down")),
        ):
            virtualmin_tasks.run_virtualmin_migration(str(migration.pk))

        migration.refresh_from_db()
        self.assertEqual((migration.status, migration.resume_after), ("quiescing", until))

    def test_a_waiting_row_is_not_run_before_its_time(self) -> None:
        migration, _ = self._held("quiescing", resume_after=timezone.now() + timedelta(minutes=5))
        VirtualminMigration.objects.filter(pk=migration.pk).update(lease_token=None, worker_lease_expires_at=None)
        step = Mock(side_effect=AssertionError("a waiting row ran before its time"))

        with patch.object(VirtualminMigrationService, "_quiesce", step):
            result = virtualmin_tasks.run_virtualmin_migration(str(migration.pk))

        self.assertEqual(result["action"], "waiting")
        step.assert_not_called()
        migration.refresh_from_db()
        self.assertIsNone(migration.lease_token)

    def test_a_due_row_resumes_even_in_a_phase_an_interruption_would_review(self) -> None:
        # A deferral is a clean checkpoint, not an interruption: backing_up's "review" policy is for a
        # worker that died mid-backup, not for one that chose to wait.
        migration, _ = self._held("backing_up", resume_after=timezone.now() - timedelta(seconds=1))
        VirtualminMigration.objects.filter(pk=migration.pk).update(lease_token=None, worker_lease_expires_at=None)
        later = timezone.now() + timedelta(minutes=5)
        seen: list[object] = []

        def step(_service: VirtualminMigrationService, row: VirtualminMigration, _token: object) -> None:
            # Cleared before the step: a stale due time would make a later interruption look like a wait.
            seen.append(VirtualminMigration.objects.get(pk=row.pk).resume_after)
            raise self._defer(later)

        with patch.object(VirtualminMigrationService, "_backup", step), patch.object(virtualmin_tasks, "schedule"):
            virtualmin_tasks.run_virtualmin_migration(str(migration.pk))

        self.assertEqual(seen, [None])
        migration.refresh_from_db()
        self.assertEqual((migration.status, migration.resume_after), ("backing_up", later))

    def test_the_reclaim_leaves_a_waiting_row_alone_and_wakes_a_due_one(self) -> None:
        migration, _ = self._held("quiescing", resume_after=timezone.now() + timedelta(minutes=5))
        stale = timezone.now() - timedelta(hours=2)
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            lease_token=None, worker_lease_expires_at=None, updated_at=stale
        )

        with patch.object(virtualmin_tasks, "enqueue_virtualmin_migration") as enqueue:
            self.assertEqual(virtualmin_tasks.reclaim_stalled_virtualmin_operations()["migrations_requeued"], 0)
            VirtualminMigration.objects.filter(pk=migration.pk).update(
                resume_after=timezone.now() - timedelta(minutes=1), updated_at=stale
            )
            self.assertEqual(virtualmin_tasks.reclaim_stalled_virtualmin_operations()["migrations_requeued"], 1)

        enqueue.assert_called_once()


class DrainCountingTests(StatesCase):
    def _drain(self, status: str) -> NodeDrain:
        return NodeDrain.objects.create(server=self.server, status=status, accounts_total=1)

    def _finish_completed(self, migration: VirtualminMigration) -> None:
        token = uuid4()
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status="repointing", lease_token=token, worker_lease_expires_at=timezone.now() + timedelta(hours=1)
        )
        migration.refresh_from_db()
        with self.captureOnCommitCallbacks(execute=True):
            VirtualminMigrationService()._finish(migration, token, "completed")

    def test_a_finished_migration_is_counted_once_on_its_drain(self) -> None:
        drain = self._drain("running")
        migration = self._start()
        VirtualminMigration.objects.filter(pk=migration.pk).update(drain=drain)
        migration.refresh_from_db()

        self._finish_completed(migration)

        drain.refresh_from_db()
        self.assertEqual(drain.accounts_migrated, 1)

    def test_a_finish_wakes_the_drain_that_waited_for_it(self) -> None:
        drain = self._drain("pending")
        migration = self._start()
        VirtualminMigration.objects.filter(pk=migration.pk).update(drain=drain)
        migration.refresh_from_db()

        with patch.object(NodeDrainService, "_enqueue") as enqueue:
            self._finish_completed(migration)

        enqueue.assert_called_once_with(drain.pk, drain.task_token)

    def test_a_drain_running_the_migration_itself_is_not_woken(self) -> None:
        drain = self._drain("running")
        migration = self._start()
        VirtualminMigration.objects.filter(pk=migration.pk).update(drain=drain)
        migration.refresh_from_db()

        with patch.object(NodeDrainService, "_enqueue") as enqueue:
            self._finish_completed(migration)

        enqueue.assert_not_called()

    def _drain_waiting_on(self, status: str) -> NodeDrain:
        drain = self._drain("pending")
        migration, _ = self._held(status, resume_after=timezone.now() + timedelta(minutes=5), drain=drain)
        VirtualminMigration.objects.filter(pk=migration.pk).update(lease_token=None, worker_lease_expires_at=None)
        NodeDrain.objects.filter(pk=drain.pk).update(current_migration=migration)
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        drain.refresh_from_db()
        return drain

    def test_a_drain_run_again_while_its_migration_waits_starts_nothing(self) -> None:
        drain = self._drain_waiting_on("quiescing")

        with patch.object(VirtualminMigrationService, "start_migration") as start:
            NodeDrainService.run(drain.pk)

        start.assert_not_called()
        drain.refresh_from_db()
        self.assertEqual(drain.status, "pending")

    def test_a_drain_whose_migration_needs_review_pauses(self) -> None:
        drain = self._drain_waiting_on("needs_review")

        with patch.object(VirtualminMigrationService, "start_migration") as start:
            NodeDrainService.run(drain.pk)

        start.assert_not_called()
        drain.refresh_from_db()
        self.assertEqual(drain.status, "paused_needs_review")
