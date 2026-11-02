"""Relative maintenance fixtures stay inside their policy across UTC day boundaries."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy
from apps.infrastructure.node_maintenance_policy import validate_policy_interval
from tests.infrastructure.maintenance_policy_fixtures import maintenance_policy_times


class MaintenanceFixtureIntervalTests(SimpleTestCase):
    def test_relative_windows_fit_across_day_boundaries_and_outside_windows_are_refused(self) -> None:
        clocks = (
            datetime(2026, 11, 1, 23, 56, 0, 123456, tzinfo=UTC),
            datetime(2026, 11, 2, 0, 0, tzinfo=UTC),
            datetime(2026, 11, 2, 0, 0, 5, tzinfo=UTC),
            datetime(2026, 11, 1, 22, 45, tzinfo=UTC),
            datetime(2026, 11, 2, 12, 0, tzinfo=UTC),
            datetime(2026, 11, 1, 23, 56, tzinfo=UTC).astimezone(ZoneInfo("Europe/Bucharest")),
        )
        offsets = (
            -timedelta(hours=1),
            -timedelta(seconds=10),
            timedelta(minutes=10),
            timedelta(hours=2),
            timedelta(hours=11, minutes=30),
            timedelta(days=3),
        )
        for clock in clocks:
            with patch("django.utils.timezone.now", return_value=clock):
                starts_time, ends_time = maintenance_policy_times()
            policy = NodeMaintenancePolicy(
                timezone="UTC",
                weekdays=list(range(7)),
                starts_time=starts_time,
                ends_time=ends_time,
                max_defer_minutes=30,
            )
            anchor = clock.astimezone(UTC)
            for offset in offsets:
                with self.subTest(clock=clock, offset=offset):
                    starts = anchor + offset
                    validate_policy_interval(policy, starts, starts + timedelta(minutes=30))
            with self.subTest(clock=clock, outside=True):
                starts = anchor + timedelta(hours=13)
                with self.assertRaisesMessage(ValidationError, "entire window must fit"):
                    validate_policy_interval(policy, starts, starts + timedelta(minutes=30))
