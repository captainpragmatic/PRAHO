"""Scheduling uses an explicit local calendar without changing accounting timezones."""

from datetime import UTC, datetime, time

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase
from django.utils import timezone

from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy
from apps.infrastructure.node_maintenance_policy import parse_staff_datetime, validate_policy_interval


class NodeMaintenancePolicyTimeTests(SimpleTestCase):
    def policy(self) -> NodeMaintenancePolicy:
        return NodeMaintenancePolicy(
            timezone="Europe/Bucharest", weekdays=[0], starts_time=time(23), ends_time=time(2), max_defer_minutes=15
        )

    def test_a_nonexistent_spring_wall_time_is_refused(self) -> None:
        with self.assertRaises(ValidationError):
            parse_staff_datetime("2027-03-28T03:30", "Europe/Bucharest")

    def test_a_repeated_autumn_wall_time_requires_an_explicit_offset(self) -> None:
        with self.assertRaises(ValidationError):
            parse_staff_datetime("2027-10-31T03:30", "Europe/Bucharest")
        early = parse_staff_datetime("2027-10-31T03:30:00+03:00", "Europe/Bucharest")
        late = parse_staff_datetime("2027-10-31T03:30:00+02:00", "Europe/Bucharest")
        self.assertNotEqual(early.astimezone(UTC), late.astimezone(UTC))

    def test_overnight_intervals_belong_to_the_starting_weekday(self) -> None:
        validate_policy_interval(
            self.policy(),
            datetime.fromisoformat("2026-11-03T00:30+02:00"),
            datetime.fromisoformat("2026-11-03T01:30+02:00"),
        )
        with self.assertRaises(ValidationError):
            validate_policy_interval(
                self.policy(),
                datetime.fromisoformat("2026-11-04T00:30+02:00"),
                datetime.fromisoformat("2026-11-04T01:30+02:00"),
            )

    def test_the_entire_window_must_fit_the_permitted_interval(self) -> None:
        with self.assertRaises(ValidationError):
            validate_policy_interval(
                self.policy(),
                datetime.fromisoformat("2026-11-02T23:30+02:00"),
                datetime.fromisoformat("2026-11-03T02:01+02:00"),
            )

    def test_naive_or_backwards_intervals_are_refused(self) -> None:
        start = datetime(2026, 11, 2, 23, 30, tzinfo=UTC)
        for starts_at, ends_at in ((start.replace(tzinfo=None), start), (start, start)):
            with self.subTest(starts_at=starts_at), self.assertRaises(ValidationError):
                validate_policy_interval(self.policy(), starts_at, ends_at)

    def test_display_resolution_does_not_activate_an_operator_timezone(self) -> None:
        active_zone = timezone.get_current_timezone_name()
        resolved = parse_staff_datetime("2026-11-02T23:30", "Europe/Bucharest")
        self.assertEqual(resolved.astimezone(UTC), datetime(2026, 11, 2, 21, 30, tzinfo=UTC))
        self.assertEqual(timezone.get_current_timezone_name(), active_zone)
