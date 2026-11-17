"""When a database over-allowance episode opens, pauses and closes: only observed readings count."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from apps.provisioning.database_overage_models import DatabaseOverageEpisode
from apps.provisioning.database_overage_service import MIB, allowance_bytes, evaluate_account, grace_period
from apps.provisioning.hosting_raise_service import RaiseTerms
from apps.provisioning.models import ServiceHostingLimits
from apps.provisioning.virtualmin_usage_models import NodeUsageSyncState, UsageReading
from apps.settings.models import SystemSetting
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.database_overage_fixtures import make_overage_account

ALLOWANCE = 1000 * MIB
OVER = {"disk_total_bytes": 1200 * MIB, "disk_db_bytes": 300 * MIB}
UNDER = {"disk_total_bytes": 800 * MIB, "disk_db_bytes": 300 * MIB}


class _Readings:
    def setUp(self):
        self.fixture = make_overage_account()
        self.start = timezone.now().replace(microsecond=0) - timedelta(days=10)
        self.fixture.usage.gauge_not_before = self.start - timedelta(days=1)
        self.fixture.usage.save(update_fields=["gauge_not_before"])
        SystemSetting.objects.create(
            key="provisioning.database_overage_enabled",
            value=True,
            default_value=False,
            data_type="boolean",
            category="provisioning",
        )
        allowance = patch("apps.provisioning.database_overage_service.allowance_bytes", return_value=ALLOWANCE)
        self.allowance = allowance.start()
        self.addCleanup(allowance.stop)

    def read(self, at, *, owner_scope=None, **disk) -> UsageReading:
        """A reading taken at `at`, published as the account's current disk reading."""
        reading = UsageReading.objects.create(
            account=self.fixture.account,
            owner_scope=owner_scope or self.fixture.usage.owner_scope,
            sync_token=uuid4(),
            server_id_snapshot=self.fixture.server.pk,
            chain_epoch=self.fixture.account.chain_epoch,
            taken_at=at,
            scan_started_at=at - timedelta(minutes=1),
            disk_files_bytes=disk["disk_total_bytes"] - disk["disk_db_bytes"],
            period_start=at - timedelta(days=1),
            period_end=at + timedelta(days=30),
            period_timezone="UTC",
            **disk,
        )
        self.fixture.usage.disk_reading = reading
        self.fixture.usage.save(update_fields=["disk_reading"])
        return reading

    def evaluate(self, at) -> str:
        return evaluate_account(self.fixture.account.pk, at=at)

    def episode(self) -> DatabaseOverageEpisode:
        return DatabaseOverageEpisode.objects.get(account=self.fixture.account)


class DatabaseOverageOpeningTests(_Readings, TestCase):
    def test_a_fresh_over_reading_opens_a_grace_episode_with_the_deadline(self):
        reading = self.read(self.start, **OVER)
        self.assertEqual(self.evaluate(self.start + timedelta(minutes=5)), "opened")
        episode = self.episode()
        self.assertEqual(episode.state, "grace")
        self.assertEqual(episode.deadline_at, self.start + timedelta(minutes=5) + timedelta(days=14))
        self.assertEqual(episode.opened_reading, reading)
        self.assertEqual(episode.last_fresh_at, self.start)
        self.assertEqual(
            (episode.domain_id, episode.installation, episode.server_id, episode.owner_scope),
            (
                self.fixture.usage.domain_id,
                self.fixture.installation,
                self.fixture.server.pk,
                self.fixture.usage.owner_scope,
            ),
        )

    def test_the_grace_period_setting_sets_the_deadline(self):
        SystemSetting.objects.create(
            key="provisioning.database_overage_grace_days",
            value=3,
            default_value=14,
            data_type="integer",
            category="provisioning",
        )
        self.assertEqual(grace_period(), timedelta(days=3))
        self.read(self.start, **OVER)
        evaluate_account(self.fixture.account.pk, at=self.start)
        self.assertEqual(self.episode().deadline_at, self.start + timedelta(days=3))

    def test_nothing_opens_without_a_fresh_known_over_reading_on_an_active_managed_account(self):
        cases = {
            "files only, no database bytes": ({"disk_total_bytes": 1200 * MIB, "disk_db_bytes": 0}, {}),
            "under": (UNDER, {}),
            "older than two hours": (OVER, {"age": timedelta(hours=2, minutes=1)}),
            "unknown allowance": (OVER, {"allowance": None}),
            "unlimited allowance": (OVER, {"allowance": 0}),
            "another owner's reading": (OVER, {"owner_scope": uuid4()}),
            "not quota managed": (OVER, {"unmanaged": True}),
            "service suspended": (OVER, {"service_status": "suspended"}),
            "flag off": (OVER, {"flag": False}),
            "a later scan failed": (OVER, {"failed_after": True}),
        }
        for name, (disk, case) in cases.items():
            with self.subTest(name):
                DatabaseOverageEpisode.objects.all().delete()
                self.allowance.return_value = case.get("allowance", ALLOWANCE)
                self.fixture.account.quota_managed = not case.get("unmanaged", False)
                self.fixture.account.save(update_fields=["quota_managed"])
                force_status(self.fixture.service, case.get("service_status", "active"))
                SystemSetting.objects.filter(key="provisioning.database_overage_enabled").update(
                    value=case.get("flag", True)
                )
                NodeUsageSyncState.objects.filter(server=self.fixture.server).delete()
                at = self.start + case.get("age", timedelta(0))
                self.read(self.start, owner_scope=case.get("owner_scope"), **disk)
                if case.get("failed_after"):
                    NodeUsageSyncState.objects.create(
                        server=self.fixture.server, outcome="unavailable", last_attempt_at=self.start + timedelta(minutes=30)
                    )
                    at = self.start + timedelta(hours=1)
                self.assertEqual(self.evaluate(at), "none")
                self.assertFalse(DatabaseOverageEpisode.objects.exists())


class DatabaseOverageClosingTests(_Readings, TestCase):
    def setUp(self):
        super().setUp()
        self.read(self.start, **OVER)
        self.evaluate(self.start)

    def hourly(self, first_hour, last_hour, disk, *, step=1) -> str:
        outcome = ""
        for hour in range(first_hour, last_hour + 1, step):
            at = self.start + timedelta(hours=hour)
            self.read(at, **disk)
            outcome = self.evaluate(at + timedelta(minutes=5))
        return outcome

    def test_twenty_four_observed_hours_under_close_a_grace_episode(self):
        self.assertEqual(self.hourly(1, 24, UNDER), "observed")  # 23 hours since the first under reading
        self.assertEqual(self.episode().state, "grace")
        self.assertEqual(self.hourly(25, 25, UNDER), "closed")
        episode = self.episode()
        self.assertEqual((episode.state, episode.close_reason), ("closed", "under_allowance"))

    def test_the_same_reading_swept_again_is_not_another_observation(self):
        self.hourly(1, 1, UNDER)
        for minutes in range(10, 25 * 60, 60):  # swept hourly for a day, never re-read
            self.evaluate(self.start + timedelta(hours=1, minutes=minutes))
        episode = self.episode()
        self.assertEqual(episode.state, "grace")
        self.assertEqual(episode.last_fresh_at, self.start + timedelta(hours=1))

    def test_an_older_reading_never_moves_the_observation_back(self):
        self.hourly(1, 5, UNDER)
        self.read(self.start + timedelta(hours=4), **OVER)  # a late, older publication, still fresh
        self.evaluate(self.start + timedelta(hours=5, minutes=30))
        episode = self.episode()
        self.assertEqual(episode.last_fresh_at, self.start + timedelta(hours=5))
        self.assertEqual(episode.below_since, self.start + timedelta(hours=1))

    def test_a_gap_of_more_than_three_hours_restarts_the_twenty_four(self):
        self.hourly(1, 12, UNDER)
        self.hourly(17, 37, UNDER)  # four hours without a reading, then 20 more hours under
        self.assertEqual(self.episode().state, "grace")
        self.assertEqual(self.hourly(38, 41, UNDER), "closed")  # 24 hours after the gap
        self.assertEqual(self.episode().below_since, self.start + timedelta(hours=17))

    def test_readings_three_hours_apart_are_continuous(self):
        """The gap that matters is between readings; a sweep a few minutes after one doesn't stretch it."""
        self.assertEqual(self.hourly(3, 24, UNDER, step=3), "observed")
        self.assertEqual(self.hourly(27, 27, UNDER), "closed")

    def test_a_sweep_three_hours_after_the_last_reading_breaks_continuity_by_itself(self):
        self.hourly(1, 10, UNDER)
        self.evaluate(self.start + timedelta(hours=13, minutes=6))
        self.assertIsNone(self.episode().below_since)

    def test_an_over_reading_restarts_the_twenty_four(self):
        self.hourly(1, 20, UNDER)
        self.hourly(21, 21, OVER)
        self.assertEqual(self.hourly(22, 45, UNDER), "observed")  # 23 hours under since the over reading
        self.assertEqual(self.hourly(46, 46, UNDER), "closed")

    def test_a_held_episode_under_for_twenty_four_hours_starts_its_release(self):
        episode = self.episode()
        episode.start_hold(token=uuid4(), generation=1)
        episode.confirm_held(digest="sha256:held")
        episode.save()
        self.assertEqual(self.hourly(1, 25, UNDER), "releasing")
        episode = self.episode()
        self.assertEqual((episode.state, episode.release_purpose), ("releasing", "under_allowance"))


class DatabaseOverageOwnershipTests(_Readings, TestCase):
    def setUp(self):
        super().setUp()
        self.read(self.start, **OVER)
        self.evaluate(self.start)

    def new_owner(self):
        self.fixture.usage.owner_scope = uuid4()
        self.fixture.usage.save(update_fields=["owner_scope"])

    def test_a_grace_episode_of_a_previous_owner_closes(self):
        self.new_owner()
        self.assertEqual(self.evaluate(self.start + timedelta(minutes=10)), "closed")
        episode = DatabaseOverageEpisode.objects.get(account=self.fixture.account)
        self.assertEqual(episode.close_reason, "ownership_changed")
        self.read(self.start + timedelta(minutes=20), **OVER)
        self.assertEqual(self.evaluate(self.start + timedelta(minutes=25)), "opened")  # the new owner's own episode

    def test_a_held_episode_of_a_previous_owner_starts_its_release(self):
        episode = self.episode()
        episode.start_hold(token=uuid4(), generation=1)
        episode.confirm_held(digest="sha256:held")
        episode.save()
        self.new_owner()
        self.assertEqual(self.evaluate(self.start + timedelta(minutes=10)), "releasing")
        episode = self.episode()
        self.assertEqual((episode.state, episode.release_purpose), ("releasing", "ownership_changed"))


class DatabaseOveragePauseTests(_Readings, TestCase):
    def setUp(self):
        super().setUp()
        self.read(self.start, **OVER)
        self.evaluate(self.start)
        self.deadline = self.episode().deadline_at

    def suspend(self, status):
        force_status(self.fixture.service, status)

    def test_the_clock_stops_while_the_service_is_inactive_and_moves_the_deadline_on_resume(self):
        self.suspend("suspended")
        self.assertEqual(self.evaluate(self.start + timedelta(days=1)), "paused")
        self.assertEqual(self.episode().deadline_at, self.deadline)
        self.suspend("active")
        self.evaluate(self.start + timedelta(days=3))
        episode = self.episode()
        self.assertIsNone(episode.paused_at)
        self.assertEqual(episode.paused_total, timedelta(days=2))
        self.assertEqual(episode.deadline_at, self.deadline + timedelta(days=2))

    def test_a_resume_near_the_deadline_still_leaves_three_days(self):
        self.suspend("suspended")
        self.evaluate(self.start + timedelta(days=13, hours=23))
        self.suspend("active")
        resumed = self.start + timedelta(days=13, hours=23, minutes=1)
        self.evaluate(resumed)
        self.assertEqual(self.episode().deadline_at, resumed + timedelta(days=3))

    def test_a_held_episode_stays_held_while_paused(self):
        episode = self.episode()
        episode.start_hold(token=uuid4(), generation=1)
        episode.confirm_held(digest="sha256:held")
        episode.save()
        self.suspend("suspended")
        self.evaluate(self.start + timedelta(days=1))
        self.assertEqual(self.episode().state, "held")


class DatabaseOverageAllowanceTests(TestCase):
    """The allowance an episode measures against: purchased plus temporary relief, never native headroom."""

    def setUp(self):
        self.fixture = make_overage_account("allowance")
        self.limits = ServiceHostingLimits.objects.get(service=self.fixture.service)  # created with the service
        self.limits.operational_revision, self.limits.operational_disk_allowance_mib = 1, 1024
        self.limits.save(update_fields=["operational_revision", "operational_disk_allowance_mib"])
        self.at = timezone.now()

    def allowance(self, *, verified=True):
        def prime(services, accounts, *, at=None):
            for service in services:
                service.__dict__["_hosting_operational_verified"] = verified

        service = type(self.fixture.service).objects.get(pk=self.fixture.service.pk)
        with patch("apps.provisioning.hosting_limit_selectors.prime_current_verification", prime):
            return allowance_bytes(service, self.fixture.account, at=self.at)

    def test_a_verified_allowance_is_the_purchased_disk_in_bytes(self):
        self.assertEqual(self.allowance(), 1024 * MIB)

    def test_active_temporary_relief_counts(self):
        terms = RaiseTerms(1, 512, self.at + timedelta(days=1))
        with patch("apps.provisioning.hosting_raise_service.current_raise_terms", return_value=terms) as current:
            self.assertEqual(self.allowance(), 1536 * MIB)
        current.assert_called_once_with(self.fixture.service.pk, self.fixture.customer.pk, at=self.at)
        self.limits.operational_disk_allowance_mib = 0
        self.limits.save(update_fields=["operational_disk_allowance_mib"])
        with patch("apps.provisioning.hosting_raise_service.current_raise_terms", return_value=terms):
            self.assertEqual(self.allowance(), 0)  # unlimited stays unlimited, relief or not

    def test_unverified_or_missing_limits_are_unknown_and_zero_is_unlimited(self):
        self.assertIsNone(self.allowance(verified=False))
        self.limits.operational_disk_allowance_mib = 0
        self.limits.save(update_fields=["operational_disk_allowance_mib"])
        self.assertEqual(self.allowance(), 0)
        self.limits.delete()
        self.assertIsNone(self.allowance())
