"""The overage sweep: notices, the deadline, the hold and its release, against a stand-in for the node."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone
from django_q.models import Schedule

from apps.audit.models import AuditEvent
from apps.common.types import Err
from apps.notifications.models import EmailLog
from apps.provisioning import database_overage_service
from apps.provisioning import database_overage_tasks as sweep_module
from apps.provisioning.database_overage_attention import episodes_needing_attention
from apps.provisioning.database_overage_delivery import setup_overage_notices
from apps.provisioning.database_overage_models import DatabaseOverageEpisode, DatabaseOverageNotice
from apps.provisioning.database_overage_service import MIB
from apps.provisioning.database_overage_tasks import SCHEDULE_NAME, sweep_database_overages
from apps.provisioning.models import ServiceHostingLimits
from apps.provisioning.virtualmin_migration_models import VirtualminMigration, account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_tasks import setup_virtualmin_scheduled_tasks
from apps.provisioning.virtualmin_usage_models import AccountUsageState, UsageReading
from apps.settings.models import SystemSetting
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.database_hold_fake import HELD_DIGEST, FakeNode, HoldRefusal
from tests.provisioning.database_overage_fixtures import make_overage_account

OVER, UNDER = 1200 * MIB, 800 * MIB


class _Sweep:
    def setUp(self):
        self.fixture = make_overage_account("sweep")
        self.start = timezone.now().replace(microsecond=0) - timedelta(days=20)
        self.fixture.usage.gauge_not_before = self.start - timedelta(days=1)
        self.fixture.usage.save(update_fields=["gauge_not_before"])
        self.flag = SystemSetting.objects.create(
            key="provisioning.database_overage_enabled",
            value=True,
            default_value=False,
            data_type="boolean",
            category="provisioning",
        )
        setup_overage_notices()
        self.node = FakeNode()
        self.busy = False
        real_busy = database_overage_service.account_busy
        for target, value in (
            ("apps.provisioning.database_overage_service.allowance_bytes", lambda *a, **k: 1000 * MIB),
            ("apps.provisioning.database_overage_tasks._gateway", lambda: self.node and self.node.module()),
            # Busy when a test says so, and whenever the real admission rule says so.
            ("apps.provisioning.database_overage_service.account_busy", lambda account, **kw: self.busy or real_busy(account, **kw)),
        ):
            patcher = patch(target, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def read(self, at, total):
        reading = UsageReading.objects.create(
            account=self.fixture.account,
            owner_scope=self.fixture.usage.owner_scope,
            sync_token=uuid4(),
            server_id_snapshot=self.fixture.server.pk,
            chain_epoch=self.fixture.account.chain_epoch,
            taken_at=at,
            scan_started_at=at - timedelta(minutes=1),
            disk_files_bytes=total - 300 * MIB,
            disk_db_bytes=300 * MIB,
            disk_total_bytes=total,
            period_start=at - timedelta(days=1),
            period_end=at + timedelta(days=30),
            period_timezone="UTC",
        )
        self.fixture.usage.disk_reading = reading
        self.fixture.usage.save(update_fields=["disk_reading"])

    def sweep(self, at):
        return sweep_database_overages(at=at)

    def episode(self) -> DatabaseOverageEpisode:
        return DatabaseOverageEpisode.objects.filter(account=self.fixture.account).latest("opened_at")

    def accept(self, kind):
        notice = DatabaseOverageNotice.objects.get(episode=self.episode(), kind=kind)
        EmailLog.objects.filter(pk=notice.email_log_id).update(status="sent", sent_at=self.start + timedelta(minutes=2))

    def actions(self, episode) -> list[str]:
        return list(
            AuditEvent.objects.filter(
                content_type=ContentType.objects.get_for_model(DatabaseOverageEpisode), object_id=str(episode.pk)
            )
            .exclude(action="status_changed")
            .order_by("timestamp")
            .values_list("action", flat=True)
        )

    def open_and_reach_deadline(self):
        """Open an episode, accept its day-0 notice, and stand at its deadline with a fresh over reading."""
        self.read(self.start, OVER)
        self.sweep(self.start + timedelta(minutes=1))
        self.accept("day0")
        self.sweep(self.start + timedelta(minutes=5))
        deadline = self.episode().deadline_at
        self.read(deadline - timedelta(hours=1), OVER)
        return deadline


class DatabaseOverageDeadlineTests(_Sweep, TestCase):
    def test_a_due_episode_is_held_then_told_with_every_step_on_record(self):
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        episode = self.episode()
        self.assertEqual((episode.state, episode.held_digest, episode.hold_generation), ("held", HELD_DIGEST, 1))
        name, call = self.node.calls[0]
        self.assertEqual(name, "hold")
        self.assertEqual(
            (call["identity"].server_id, call["identity"].domain_id, call["identity"].installation, call["token"]),
            (episode.server_id, episode.domain_id, episode.installation, episode.hold_token),
        )
        self.sweep(deadline + timedelta(minutes=20))
        self.assertTrue(DatabaseOverageNotice.objects.filter(episode=episode, kind="day14").exists())
        self.assertEqual(
            self.actions(episode),
            [
                "database_overage_opened",
                "database_overage_notice_sent",
                "database_overage_hold_requested",
                "database_overage_hold_applied",
            ],
        )

    def test_the_sweep_records_the_day_zero_acceptance_itself(self):
        self.read(self.start, OVER)
        self.sweep(self.start + timedelta(minutes=1))
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        self.assertIsNone(notice.accepted_at)
        self.accept("day0")
        self.sweep(self.start + timedelta(minutes=5))
        notice.refresh_from_db()
        self.assertIsNotNone(notice.accepted_at)

    def assert_deferred(self, prevent):
        deadline = self.open_and_reach_deadline()
        prevent()
        self.assertEqual(self.sweep(deadline + timedelta(minutes=5)).get("deferred"), 1)
        episode = self.episode()
        self.assertEqual((episode.state, episode.deferred_since), ("grace", deadline + timedelta(minutes=5)))
        self.assertNotIn("hold", self.node.actions() if self.node else [])

    def test_no_hold_with_the_flag_off(self):
        self.assert_deferred(lambda: SystemSetting.objects.filter(pk=self.flag.pk).update(value=False))

    def test_no_hold_before_day_zero_was_accepted(self):
        def not_accepted():
            DatabaseOverageNotice.objects.update(accepted_at=None)
            EmailLog.objects.update(status="queued")

        self.assert_deferred(not_accepted)

    def test_no_hold_without_a_fresh_over_reading(self):
        self.assert_deferred(lambda: self.read(self.episode().deadline_at - timedelta(hours=1), UNDER))

    def test_no_hold_while_suspended_for_a_migration(self):
        self.assert_deferred(
            lambda: DatabaseOverageEpisode.objects.update(suspended_for="migration", suspended_migration_id=uuid4())
        )

    def test_no_hold_while_an_operation_runs(self):
        self.assert_deferred(lambda: setattr(self, "busy", True))

    def test_an_episode_naming_another_node_waits_for_the_collector_there_then_follows(self):
        def moved_before_collected():
            DatabaseOverageEpisode.objects.update(server_id=uuid4())  # the node the episode was opened on
            AccountUsageState.objects.filter(account=self.fixture.account).update(domain_id="")

        self.assert_deferred(moved_before_collected)
        self.assertIn("identity_unknown", self.sweep_until_attention())
        AccountUsageState.objects.filter(account=self.fixture.account).update(domain_id="17001")
        self.sweep(self.episode().deadline_at + timedelta(hours=24, minutes=20))
        episode = self.episode()
        self.assertEqual((episode.state, episode.server_id), ("held", self.fixture.server.pk))
        self.assertEqual(self.node.calls[-1][1]["identity"].server_id, self.fixture.server.pk)

    def sweep_until_attention(self):
        self.read(self.episode().deadline_at + timedelta(hours=24), OVER)
        self.sweep(self.episode().deadline_at + timedelta(hours=24, minutes=6))
        return self.episode().last_error

    def test_a_domain_recreated_on_the_same_node_is_held_under_its_new_id(self):
        deadline = self.open_and_reach_deadline()
        AccountUsageState.objects.filter(account=self.fixture.account).update(domain_id="17999")  # recreated
        self.sweep(deadline + timedelta(minutes=5))
        episode = self.episode()
        self.assertEqual((episode.state, episode.domain_id), ("held", "17999"))
        self.assertEqual(self.node.calls[-1][1]["identity"].domain_id, "17999")

    def test_an_identity_the_collector_lost_waits_instead_of_holding_the_old_one(self):
        deadline = self.open_and_reach_deadline()
        AccountUsageState.objects.filter(account=self.fixture.account).update(domain_id="")  # reset by a recreate
        self.sweep(deadline + timedelta(minutes=5))
        self.assertEqual(self.episode().state, "grace")
        self.assertNotIn("hold", self.node.actions())

    def test_no_hold_when_a_pending_assignment_covers_the_usage(self):
        self.assert_deferred(self.pending_assignment)

    def pending_assignment(self):
        limits = ServiceHostingLimits.objects.get(service=self.fixture.service)
        limits.revision, limits.operational_revision, limits.disk_allowance_mib = 3, 2, 4096
        limits.save(update_fields=["revision", "operational_revision", "disk_allowance_mib"])

    def test_a_deferral_past_a_day_asks_staff(self):
        deadline = self.open_and_reach_deadline()
        self.busy = True
        self.sweep(deadline + timedelta(minutes=5))
        self.assertEqual(self.episode().last_error, "")
        self.read(deadline + timedelta(hours=24), OVER)  # still over, still busy, a day on
        self.sweep(deadline + timedelta(hours=24, minutes=6))
        self.assertIn("active_operation", self.episode().last_error)

    def test_a_slow_sweep_judges_the_reading_at_the_time_of_the_decision(self):
        deadline = self.open_and_reach_deadline()  # the over reading is from an hour before the deadline
        clock = [deadline + timedelta(minutes=55)]  # 1h55m old when the sweep starts: still fresh
        evaluate = sweep_module.evaluate_account

        def slow_evaluation(account_id, *, at):
            self.assertIsNone(at)  # each account reads the clock itself, once its locks are held
            clock[0] += timedelta(minutes=30)  # other accounts' work takes the sweep past the two hours
            return evaluate(account_id, at=at)

        with (
            patch("django.utils.timezone.now", side_effect=lambda: clock[0]),
            patch.object(sweep_module, "evaluate_account", side_effect=slow_evaluation),
        ):
            sweep_database_overages()
        episode = self.episode()
        self.assertEqual(episode.state, "grace")
        self.assertNotIn("hold", self.node.actions())

    def test_a_later_episode_takes_the_next_generation(self):
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        first = self.episode()
        first.start_release("waived")
        first.save()
        self.sweep(deadline + timedelta(minutes=10))
        self.assertEqual(self.episode().state, "closed")
        self.start = deadline + timedelta(hours=1)
        self.open_and_reach_deadline()
        self.sweep(self.episode().deadline_at + timedelta(minutes=5))
        self.assertEqual(self.episode().hold_generation, 2)


class DatabaseOverageHoldOutcomeTests(_Sweep, TestCase):
    def test_sessions_still_open_wait_for_a_verify_before_held(self):
        self.node.hold_answer = "sessions"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        self.assertEqual((self.episode().state, self.episode().sessions_remaining), ("holding", [41]))
        self.sweep(deadline + timedelta(minutes=20))
        self.assertEqual(self.episode().state, "held")
        self.assertEqual(self.node.actions()[-1], "verify")

    def test_a_receipt_for_another_request_never_confirms_a_hold(self):
        original = self.node.hold

        def answer_for_an_older_generation(identity, *, token, generation):
            return original(identity, token=token, generation=generation - 1)

        self.node.hold = answer_for_an_older_generation
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        self.assertEqual(self.episode().state, "holding")

    def test_a_hold_whose_request_never_reached_the_node_is_sent_again(self):
        self.node.hold_answer = "undelivered"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        token = self.episode().hold_token
        self.sweep(deadline + timedelta(minutes=20))
        self.assertEqual(self.episode().state, "held")
        self.assertEqual(self.node.actions(), ["hold", "verify", "hold"])
        self.assertEqual(self.node.calls[-1][1]["token"], token)  # the same decision, not a new one

    def test_a_busy_node_or_a_live_barrier_is_waited_out_not_refused(self):
        for answer in ("busy", "barrier"):
            with self.subTest(answer=answer):
                DatabaseOverageEpisode.objects.all().delete()
                self.node = FakeNode(hold_answer=answer)
                deadline = self.open_and_reach_deadline()
                self.sweep(deadline + timedelta(minutes=5))
                episode = self.episode()
                self.assertEqual((episode.state, episode.hold_refused_at), ("holding", None))
                self.read(deadline + timedelta(minutes=15), OVER)
                self.sweep(deadline + timedelta(minutes=20))
                self.assertEqual(self.episode().state, "held")
                self.assertEqual(self.node.actions(), ["hold", "verify", "hold"])

    def test_a_resent_hold_never_reaches_the_node_before_a_deadline_moved_by_a_pause(self):
        """The 14 days are a promise: a hold, a resent one included, never applies before the deadline."""
        self.node.hold_answer = "undelivered"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))  # holding: the request never reached the node
        node, self.node = self.node, None  # the node goes away
        force_status(self.fixture.service, "suspended")
        self.sweep(deadline + timedelta(minutes=10))
        force_status(self.fixture.service, "active")
        self.sweep(deadline + timedelta(days=2, minutes=10))  # resumed: the deadline moved later
        moved = self.episode().deadline_at
        self.assertGreater(moved, deadline + timedelta(days=2))
        self.read(moved - timedelta(minutes=90), OVER)
        self.node = node  # the node comes back an hour before the moved deadline
        self.sweep(moved - timedelta(hours=1))
        self.assertEqual(node.actions().count("hold"), 1)
        self.assertNotEqual(self.episode().state, "held")

    def test_a_not_held_answer_about_another_request_changes_nothing(self):
        self.node.hold_answer = "undelivered"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        original = self.node.verify

        def about_another_generation(identity, *, generation):
            return original(identity, generation=generation + 7)

        self.node.verify = about_another_generation
        self.sweep(deadline + timedelta(minutes=20))
        self.assertEqual(self.node.actions(), ["hold", "verify"])
        self.assertEqual(self.episode().state, "holding")

    def test_an_undelivered_hold_is_withdrawn_if_it_no_longer_qualifies(self):
        self.node.hold_answer = "undelivered"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        self.read(deadline + timedelta(minutes=10), UNDER)  # usage fell under before the retry
        self.sweep(deadline + timedelta(minutes=20))
        self.assertNotEqual(self.node.actions()[-1], "hold")
        self.sweep(deadline + timedelta(minutes=35))
        episode = self.episode()
        self.assertEqual((episode.state, episode.hold_refused_at), ("grace", None))

    def test_a_late_refusal_never_releases_a_newer_hold(self):
        deadline = self.open_and_reach_deadline()
        self.node.hold_answer = "undelivered"
        self.sweep(deadline + timedelta(minutes=5))
        stale = self.node.hold

        def refused_after_a_newer_hold(identity, *, token, generation):
            current = self.episode()  # meanwhile the hold landed, was released for a window and held again
            current.start_release("extend")
            current.save()
            current.confirm_released_to_grace()
            current.save()
            current.start_hold(token=uuid4(), generation=generation + 1)
            current.save()
            self.node.hold_answer = "refused"
            return stale(identity, token=token, generation=generation)

        self.node.hold = refused_after_a_newer_hold
        self.sweep(deadline + timedelta(minutes=20))
        episode = self.episode()
        self.assertEqual((episode.state, episode.hold_generation, episode.hold_refused_at), ("holding", 2, None))

    def test_a_stale_release_receipt_never_settles_a_newer_hold(self):
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        episode = self.episode()
        episode.start_release("extend")
        episode.save()
        original = self.node.release

        def newer_hold_meanwhile(identity, *, generation):
            answer = original(identity, generation=generation)
            current = self.episode()  # another worker finishes this release and starts the next hold
            current.confirm_released_to_grace()
            current.save()
            current.start_hold(token=uuid4(), generation=generation + 1)
            current.save()
            current.start_release("waived")
            current.save()
            return answer

        self.node.release = newer_hold_meanwhile
        self.sweep(deadline + timedelta(minutes=20))
        episode = self.episode()
        self.assertEqual((episode.state, episode.hold_generation), ("releasing", 2))

    def test_a_lost_hold_answer_is_verified_before_anything_else(self):
        self.node.hold_answer = "lost_response"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        self.assertEqual(self.episode().state, "holding")
        self.node.verify_answer = "sessions"
        self.sweep(deadline + timedelta(minutes=20))
        self.assertEqual(self.episode().state, "holding")
        self.node.verify_answer = "held"
        self.sweep(deadline + timedelta(minutes=35))
        self.assertEqual(self.episode().state, "held")
        self.assertEqual(self.node.actions(), ["hold", "verify", "verify"])

    def test_drift_found_while_holding_sends_the_same_hold_again(self):
        self.node.hold_answer = "lost_response"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        episode = self.episode()
        self.assertEqual(episode.state, "holding")
        self.node.hold_answer, self.node.verify_answer = "held", "drift"  # a grant came back before the answer
        self.sweep(deadline + timedelta(minutes=20))
        self.assertEqual(self.node.actions(), ["hold", "verify", "hold"])
        resent = self.node.calls[-1][1]
        self.assertEqual((resent["token"], resent["generation"]), (episode.hold_token, episode.hold_generation))
        self.assertEqual(self.episode().state, "held")

    def test_an_under_reading_after_the_over_one_stops_the_hold_even_after_a_gap(self):
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline - timedelta(minutes=55))  # the over reading counts
        self.read(deadline - timedelta(minutes=15), UNDER)
        self.sweep(deadline - timedelta(minutes=10))  # then an under one; then no reading for 3 hours
        self.assertEqual(self.sweep(deadline + timedelta(hours=3, minutes=10)).get("deferred"), 1)
        self.assertNotIn("hold", self.node.actions())

    def test_a_refused_hold_stays_with_staff_whatever_is_logged_later(self):
        self.node.hold_answer = "refused"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        self.sweep(deadline + timedelta(minutes=20))
        self.assertIsNotNone(self.episode().hold_refused_at)
        for hours in (25, 50):
            self.read(deadline + timedelta(hours=hours) - timedelta(minutes=30), OVER)  # still over, still due
            self.sweep(deadline + timedelta(hours=hours))
        self.assertEqual(self.node.actions(), ["hold", "fence", "release"])

    def test_a_refused_hold_is_undone_and_left_for_staff(self):
        self.node.hold_answer = "refused"
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        episode = self.episode()
        self.assertEqual((episode.state, episode.release_purpose), ("releasing", "hold_refused"))
        token = episode.hold_token
        self.sweep(deadline + timedelta(minutes=20))
        episode = self.episode()
        self.assertEqual(episode.state, "grace")
        self.assertIn("shared_username", episode.last_error)
        self.assertEqual(self.node.actions(), ["hold", "fence", "release"])
        self.assertIn(token, self.node.fenced)
        self.sweep(deadline + timedelta(minutes=35))
        self.assertEqual(self.node.actions(), ["hold", "fence", "release"])  # not retried until staff decide


class DatabaseOverageIntentAuditTests(_Sweep, TestCase):
    """The decision is on record before the node is asked, so a worker dying mid-call still leaves a trace."""

    def test_a_hold_whose_worker_died_after_the_node_acted_is_on_record(self):
        original = self.node.hold

        def the_worker_dies_after_the_node_acted(identity, *, token, generation):
            original(identity, token=token, generation=generation)
            raise SystemExit("worker killed before the answer was saved")

        self.node.hold = the_worker_dies_after_the_node_acted
        deadline = self.open_and_reach_deadline()
        with self.assertRaises(SystemExit):
            self.sweep(deadline + timedelta(minutes=5))
        episode = self.episode()
        self.assertEqual(episode.state, "holding")
        self.assertEqual(self.actions(episode)[-1], "database_overage_hold_requested")
        self.assertNotIn("database_overage_hold_applied", self.actions(episode))

    def test_a_release_whose_worker_died_after_the_node_acted_is_on_record(self):
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        episode = self.episode()
        episode.start_release("waived")
        episode.save()
        original = self.node.release

        def the_worker_dies_after_the_node_acted(identity, *, generation):
            original(identity, generation=generation)
            raise SystemExit("worker killed before the answer was saved")

        self.node.release = the_worker_dies_after_the_node_acted
        with self.assertRaises(SystemExit):
            self.sweep(deadline + timedelta(minutes=20))
        episode = self.episode()
        self.assertEqual(episode.state, "releasing")
        self.assertEqual(self.actions(episode)[-1], "database_overage_release_requested")
        with self.assertRaises(SystemExit):
            self.sweep(deadline + timedelta(minutes=35))  # the next worker dies the same way
        attempts = AuditEvent.objects.filter(
            object_id=str(episode.pk), action="database_overage_release_requested"
        ).values_list("new_values__attempt", flat=True)
        self.assertEqual(sorted(attempts), [1, 2])  # each attempt numbered, dead workers included


class DatabaseOverageReleaseTests(_Sweep, TestCase):
    def held(self):
        deadline = self.open_and_reach_deadline()
        self.sweep(deadline + timedelta(minutes=5))
        self.assertEqual(self.episode().state, "held")
        return deadline

    def test_a_hold_is_fenced_then_released_and_the_episode_closes(self):
        deadline = self.held()
        token = self.episode().hold_token
        for hour in range(1, 26):
            self.read(deadline + timedelta(hours=hour), UNDER)
            self.sweep(deadline + timedelta(hours=hour, minutes=5))
        episode = self.episode()
        self.assertEqual((episode.state, episode.close_reason), ("closed", "under_allowance"))
        self.assertEqual(self.node.actions()[-2:], ["fence", "release"])
        self.assertEqual(self.node.calls[-2][1]["token"], token)
        self.assertEqual(
            self.actions(episode)[-2:], ["database_overage_hold_released", "database_overage_closed"]
        )

    def test_an_uncertain_release_is_tried_again(self):
        self.held()
        episode = self.episode()
        episode.start_release("waived")
        episode.save()
        self.node.release_answer = "uncertain"
        self.sweep(self.episode().deadline_at + timedelta(hours=1))
        episode = self.episode()
        self.assertEqual((episode.state, episode.attempts), ("releasing", 1))
        self.node.release_answer = "released"
        self.sweep(self.episode().deadline_at + timedelta(hours=2))
        self.assertEqual(self.episode().state, "closed")

    def test_a_release_for_a_server_record_gone_waits_and_never_stops_the_sweep(self):
        self.held()
        DatabaseOverageEpisode.objects.update(server_id=uuid4())
        episode = self.episode()
        episode.start_release("waived")
        episode.save()
        outcomes = self.sweep(self.episode().deadline_at + timedelta(hours=1))
        episode = self.episode()
        self.assertNotIn("failed", outcomes)
        self.assertEqual((episode.state, episode.attempts), ("releasing", 1))
        self.assertIn("server_missing", episode.last_error)
        self.assertEqual(self.node.actions()[-1:], ["hold"])  # nothing reached the node for the release

    def writer(self, operation="restore_domain", status="running"):
        return VirtualminProvisioningJob.objects.create(
            operation=operation,
            account=self.fixture.account,
            server=self.fixture.server,
            status=status,
            correlation_id=f"writer-{uuid4()}",
        )

    def releasing(self):
        self.held()
        episode = self.episode()
        episode.start_release("waived")
        episode.save()
        self.node.calls.clear()
        return episode.deadline_at

    def test_a_release_waits_for_a_live_writer_of_the_same_grants(self):
        deadline = self.releasing()
        for operation, status in (("restore_domain", "running"), ("apply_hosting_limits", "pending")):
            with self.subTest(operation=operation):
                job = self.writer(operation, status)
                self.assertEqual(self.sweep(deadline + timedelta(hours=1)).get("release_waiting"), 1)
                episode = self.episode()
                self.assertEqual((episode.state, episode.attempts, self.node.actions()), ("releasing", 0, []))
                self.assertIn(operation, episode.last_error)
                self.assertNotIn("database_overage_release_requested", self.actions(episode))
                job.delete()
        self.sweep(deadline + timedelta(hours=2))
        self.assertEqual((self.episode().state, self.node.actions()), ("closed", ["fence", "release"]))

    def test_a_release_waits_for_a_live_migration_but_never_for_an_attention_claim(self):
        deadline = self.releasing()
        target = make_overage_account("target").server
        migration = VirtualminMigration.objects.create(
            account=self.fixture.account, source_server=self.fixture.server, target_server=target, status="pending"
        )
        self.assertEqual(self.sweep(deadline + timedelta(hours=1)).get("release_waiting"), 1)
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="needs_review")
        self.writer("restore_domain", "attention")
        self.sweep(deadline + timedelta(hours=2))
        self.assertEqual(self.episode().state, "closed")

    def test_a_release_waiting_over_a_day_asks_staff(self):
        deadline = self.releasing()
        self.writer()
        self.sweep(deadline + timedelta(hours=1))
        self.assertNotIn(self.episode(), episodes_needing_attention(at=deadline + timedelta(hours=2)))
        self.sweep(deadline + timedelta(hours=25, minutes=5))
        self.assertIn(self.episode(), episodes_needing_attention(at=deadline + timedelta(hours=25, minutes=10)))

    def test_a_hold_on_a_domain_since_recreated_is_abandoned_for_staff_not_retried(self):
        deadline = self.held()
        old = self.episode()
        self.node.calls.clear()
        AccountUsageState.objects.filter(account=self.fixture.account).update(domain_id="17999")
        self.sweep(deadline + timedelta(hours=2))
        episode = self.episode()
        self.assertEqual(self.node.actions(), [])  # never asked about the obsolete domain
        self.assertEqual(episode.state, "grace")
        self.assertIsNotNone(episode.hold_refused_at)  # staff decide, the sweep doesn't re-hold on its own
        self.assertIn("identity changed", episode.last_error)
        released = AuditEvent.objects.filter(object_id=str(episode.pk), action="database_overage_hold_released").last()
        self.assertEqual(
            (released.new_values["abandoned"], released.new_values["domain_id"]), (True, old.domain_id)
        )
        self.assertFalse(account_has_active_operation(self.fixture.account))

    def test_a_release_on_a_domain_since_recreated_ends_without_the_node(self):
        deadline = self.held()
        episode = self.episode()
        episode.start_release("waived")
        episode.save()
        self.node.calls.clear()
        AccountUsageState.objects.filter(account=self.fixture.account).update(domain_id="17999")
        self.sweep(deadline + timedelta(hours=2))
        episode = self.episode()
        self.assertEqual((episode.state, episode.close_reason, self.node.actions()), ("closed", "waived", []))

    def test_an_installation_change_under_a_hold_stops_node_calls_and_asks_staff(self):
        deadline = self.held()
        self.node.calls.clear()
        AccountUsageState.objects.filter(account=self.fixture.account).update(installation=uuid4())
        self.sweep(deadline + timedelta(hours=2))
        episode = self.episode()
        self.assertEqual((episode.state, self.node.actions()), ("held", []))
        self.assertIn("installation changed", episode.last_error)
        self.assertIn(episode, episodes_needing_attention(at=deadline + timedelta(hours=2)))

    def test_a_held_episode_is_verified_hourly_and_drift_is_recorded(self):
        deadline = self.held()
        self.node.calls.clear()
        self.sweep(deadline + timedelta(minutes=20))
        self.assertNotIn("verify", self.node.actions())  # verified within the hour already
        self.node.verify_answer = "drift"
        self.busy = True  # the re-hold waits, so the drift stays on record
        self.read(deadline + timedelta(hours=1), OVER)
        self.sweep(deadline + timedelta(hours=1, minutes=10))
        episode = self.episode()
        self.assertTrue(episode.needs_reconcile)
        self.assertEqual(self.actions(episode)[-1], "database_hold_drift")

    def completed(self, operation):
        job = self.writer(operation, "running")
        job.mark_completed({})

    def test_a_completed_restore_is_reconciled_by_a_new_generation_at_the_next_sweep(self):
        deadline = self.held()
        held = self.episode()
        self.node.calls.clear()
        self.completed("restore_domain")
        self.assertTrue(self.episode().needs_reconcile)
        self.node.verify_answer = "drift"  # the restore put the customer's grants back
        self.sweep(deadline + timedelta(minutes=20))  # within the hour: a reconcile doesn't wait for it
        episode = self.episode()
        self.assertEqual(self.node.actions(), ["verify", "fence", "hold"])
        self.assertEqual(self.node.calls[1][1]["token"], held.hold_token)  # the old token, fenced first
        self.assertEqual(
            (episode.state, episode.hold_generation, episode.needs_reconcile), ("held", held.hold_generation + 1, False)
        )
        self.assertNotEqual(episode.hold_token, held.hold_token)
        requested = AuditEvent.objects.filter(
            object_id=str(episode.pk), action="database_overage_hold_requested"
        ).order_by("timestamp")
        self.assertEqual(requested.last().new_values.get("reason"), "reconcile")

    def test_a_completed_create_flags_and_other_jobs_do_not(self):
        self.held()
        self.completed("backup_domain")
        self.writer("restore_domain", "running").mark_failed("the restore stopped before any grant")
        self.assertFalse(self.episode().needs_reconcile)  # completed only, as the plan names it
        self.completed("create_domain")
        self.assertTrue(self.episode().needs_reconcile)

    def test_a_clean_verify_after_a_restore_holds_on_as_it_is(self):
        deadline = self.held()
        self.node.calls.clear()
        self.completed("restore_domain")
        self.sweep(deadline + timedelta(minutes=20))
        episode = self.episode()
        self.assertEqual(self.node.actions(), ["verify"])
        self.assertEqual((episode.state, episode.needs_reconcile), ("held", False))

    def test_a_reconcile_waits_while_the_account_is_busy_or_the_flag_is_off(self):
        deadline = self.held()
        self.node.verify_answer = "drift"
        for block, unblock in (
            (lambda: setattr(self, "busy", True), lambda: setattr(self, "busy", False)),
            (
                lambda: SystemSetting.objects.filter(pk=self.flag.pk).update(value=False),
                lambda: SystemSetting.objects.filter(pk=self.flag.pk).update(value=True),
            ),
        ):
            with self.subTest(block=block):
                self.node.calls.clear()
                block()
                self.sweep(deadline + timedelta(hours=2))
                episode = self.episode()
                self.assertEqual((episode.state, episode.needs_reconcile), ("held", True))
                self.assertNotIn("hold", self.node.actions())
                self.assertIn("re-hold", episode.last_error)
                unblock()
        self.sweep(deadline + timedelta(hours=3))
        self.assertEqual((self.episode().state, self.episode().hold_generation), ("held", 2))

    def test_a_rehold_whose_fence_is_lost_stays_held_and_tries_again(self):
        deadline = self.held()
        generation = self.episode().hold_generation
        self.node.calls.clear()
        self.node.verify_answer = "drift"
        self.node.fence = lambda identity, *, token: Err(HoldRefusal("uncertain", "no response"))
        self.sweep(deadline + timedelta(hours=2))
        episode = self.episode()
        self.assertEqual((episode.state, episode.hold_generation, episode.needs_reconcile), ("held", generation, True))
        self.assertIn("re-hold pending", episode.last_error)
        self.assertNotIn("hold", self.node.actions())

    def test_an_operation_admitted_while_the_old_token_is_fenced_stops_the_rehold(self):
        deadline = self.held()
        generation = self.episode().hold_generation
        self.node.calls.clear()
        self.node.verify_answer = "drift"
        fence = self.node.fence

        def a_backup_starts_meanwhile(identity, *, token):
            self.busy = True
            return fence(identity, token=token)

        self.node.fence = a_backup_starts_meanwhile
        self.sweep(deadline + timedelta(hours=2))
        episode = self.episode()
        self.assertEqual((episode.state, episode.hold_generation), ("held", generation))
        self.assertIn("re-hold deferred: active_operation", episode.last_error)
        self.assertEqual(self.node.actions(), ["verify", "fence"])

    def test_an_undelivered_rehold_is_sent_again_on_the_rehold_terms_not_withdrawn(self):
        deadline = self.held()
        self.node.verify_answer, self.node.hold_answer = "drift", "undelivered"
        self.sweep(deadline + timedelta(hours=2))
        episode = self.episode()
        self.assertEqual((episode.state, episode.hold_generation), ("holding", 2))
        # Hours later, with no fresh reading: a first hold would be withdrawn, a re-hold is sent again.
        self.node.verify_answer = "held"
        self.sweep(deadline + timedelta(hours=6))
        episode = self.episode()
        self.assertEqual((episode.state, episode.hold_generation, episode.needs_reconcile), ("held", 2, False))
        self.assertEqual(self.node.actions()[-2:], ["verify", "hold"])

    def test_a_restore_finished_by_its_worker_flags_the_hold_for_reconcile(self):
        self.held()
        token = uuid4()
        job = self.writer("restore_domain", "running")
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(execution_token=token)
        self.assertEqual(VirtualminProvisioningJob.finish_execution(job.pk, token, "completed", ""), 1)
        self.assertTrue(self.episode().needs_reconcile)

    def test_a_refused_rehold_releases_to_staff(self):
        deadline = self.held()
        self.node.verify_answer, self.node.hold_answer = "drift", "refused"
        self.sweep(deadline + timedelta(hours=2))
        episode = self.episode()
        self.assertEqual((episode.state, episode.release_purpose), ("releasing", "hold_refused"))
        self.assertIsNotNone(episode.hold_refused_at)

    def test_drift_is_cleared_by_a_clean_verify_and_by_a_release(self):
        deadline = self.held()
        self.busy = True  # no re-hold: the drift stays until a clean verify or a release clears it
        self.node.verify_answer = "drift"
        self.sweep(deadline + timedelta(hours=1, minutes=10))
        self.assertTrue(self.episode().needs_reconcile)
        self.node.verify_answer = "held"
        self.sweep(deadline + timedelta(hours=1, minutes=25))  # needs_reconcile asks for a verify at once
        self.assertFalse(self.episode().needs_reconcile)
        self.node.verify_answer = "drift"
        self.sweep(deadline + timedelta(hours=3))
        episode = self.episode()
        self.assertTrue(episode.needs_reconcile)
        episode.start_release("extend")
        episode.save()
        self.sweep(deadline + timedelta(hours=3, minutes=15))
        self.assertEqual((self.episode().state, self.episode().needs_reconcile), ("grace", False))

    def test_an_older_clean_verify_never_erases_newer_drift(self):
        deadline = self.held()
        original = self.node.verify

        def drift_recorded_while_this_answer_travels(identity, *, generation):
            answer = original(identity, generation=generation)  # clean
            DatabaseOverageEpisode.objects.filter(pk=self.episode().pk).update(needs_reconcile=True)  # another worker
            return answer

        self.node.verify = drift_recorded_while_this_answer_travels
        self.sweep(deadline + timedelta(hours=1, minutes=10))
        self.assertTrue(self.episode().needs_reconcile)

    def test_drift_evidence_is_kept_even_when_an_older_clean_answer_saved_first(self):
        deadline = self.held()
        self.node.verify_answer = "drift"
        original = self.node.verify

        def a_clean_answer_saves_first(identity, *, generation):
            answer = original(identity, generation=generation)  # drift
            episode = self.episode()
            episode.verified_at = deadline + timedelta(hours=1)  # another worker's clean answer, saved meanwhile
            episode.save()
            return answer

        self.node.verify = a_clean_answer_saves_first
        self.busy = True  # the re-hold waits, so the drift stays on record
        self.sweep(deadline + timedelta(hours=1, minutes=10))
        self.assertTrue(self.episode().needs_reconcile)
        self.assertEqual(self.actions(self.episode())[-1], "database_hold_drift")

    def test_a_paused_held_episode_stays_held(self):
        deadline = self.held()
        force_status(self.fixture.service, "suspended")
        self.sweep(deadline + timedelta(hours=2))
        self.assertEqual(self.episode().state, "held")


class DatabaseOverageScheduleTests(TestCase):
    def test_the_sweep_runs_every_fifteen_minutes(self):
        setup_virtualmin_scheduled_tasks()
        schedule = Schedule.objects.get(name=SCHEDULE_NAME)
        self.assertEqual(
            (schedule.func, schedule.minutes), ("apps.provisioning.database_overage_tasks.sweep_database_overages", 15)
        )
