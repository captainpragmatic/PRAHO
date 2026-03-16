from __future__ import annotations

from datetime import datetime
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import SimpleTestCase
from django.utils import timezone

from apps.common.partitioning import EventPartitionPolicy, EventPartitionService


class TestEventPartitionService(SimpleTestCase):
    def test_plan_operations_uses_expected_windows(self) -> None:
        service = EventPartitionService()
        reference_time = datetime(2026, 3, 11, tzinfo=timezone.get_current_timezone())

        plan = service.plan_operations(reference_time=reference_time)

        self.assertEqual(plan["audit_events"]["detach_before"], "2025-12-01")
        self.assertEqual(plan["integration_webhook_events"]["detach_before"], "2025-12-01")
        self.assertEqual(plan["billing_usage_events"]["detach_before"], "2025-02-01")
        self.assertIn("audit_events_2026_03", plan["audit_events"]["create_partitions"])
        self.assertIn("billing_usage_events_2026_06", plan["billing_usage_events"]["create_partitions"])

    def test_status_reports_unsupported_backend_on_sqlite(self) -> None:
        service = EventPartitionService()

        status = service.get_status()

        self.assertEqual(status["audit_events"]["status"], "unsupported_backend")
        self.assertEqual(status["billing_usage_events"]["keep_attached_months"], 13)


class TestManageEventPartitionsCommand(SimpleTestCase):
    @patch("apps.common.management.commands.manage_event_partitions.EventPartitionService")
    def test_plan_json_output(self, mock_service_cls) -> None:
        mock_service = mock_service_cls.return_value
        mock_service.plan_operations.return_value = {"audit_events": {"detach_before": "2025-12-01"}}

        with self.settings(USE_TZ=True):
            out = self._call("--action=plan", "--json")

        self.assertIn('"audit_events"', out)
        self.assertIn('"detach_before": "2025-12-01"', out)

    @patch("apps.common.management.commands.manage_event_partitions.EventPartitionService")
    def test_ensure_future_dry_run_output(self, mock_service_cls) -> None:
        mock_service = mock_service_cls.return_value
        mock_service.ensure_future_partitions.return_value = ["CREATE TABLE test_partition ...;"]

        out = self._call("--action=ensure-future", "--dry-run")

        self.assertIn("CREATE TABLE test_partition ...;", out)
        self.assertIn("Dry run only", out)

    def _call(self, *args: str) -> str:
        out = StringIO()
        call_command("manage_event_partitions", *args, stdout=out)
        return out.getvalue()


class TestEventPartitionPolicyValidation(SimpleTestCase):
    """Verify __post_init__ rejects invalid SQL identifiers."""

    def test_valid_identifiers_accepted(self) -> None:
        policy = EventPartitionPolicy(
            slug="test_events",
            table_name="test_events",
            partition_column="created_at",
            keep_attached_months=3,
            create_ahead_months=3,
        )
        self.assertEqual(policy.table_name, "test_events")

    def test_invalid_table_name_rejected(self) -> None:
        with self.assertRaises(ValueError, msg="Should reject SQL injection in table_name"):
            EventPartitionPolicy(
                slug="test",
                table_name="test; DROP TABLE users--",
                partition_column="created_at",
                keep_attached_months=3,
                create_ahead_months=3,
            )

    def test_invalid_partition_column_rejected(self) -> None:
        with self.assertRaises(ValueError, msg="Should reject uppercase in column name"):
            EventPartitionPolicy(
                slug="test",
                table_name="test_events",
                partition_column="CREATED_AT",
                keep_attached_months=3,
                create_ahead_months=3,
            )

    def test_empty_slug_rejected(self) -> None:
        with self.assertRaises(ValueError):
            EventPartitionPolicy(
                slug="",
                table_name="test_events",
                partition_column="created_at",
                keep_attached_months=3,
                create_ahead_months=3,
            )


class TestEventPartitionServiceEdgeCases(SimpleTestCase):
    """Test partition service failure modes."""

    def test_ensure_future_returns_empty_on_sqlite(self) -> None:
        """On SQLite (non-PostgreSQL), ensure_future_partitions is a no-op."""
        service = EventPartitionService()
        result = service.ensure_future_partitions(dry_run=True)
        self.assertEqual(result, [])

    def test_plan_operations_with_none_reference_time(self) -> None:
        """plan_operations with None reference_time should use current time."""
        service = EventPartitionService()
        plan = service.plan_operations(reference_time=None)
        # Should produce a valid plan for all 3 policies
        self.assertEqual(len(plan), 3)
        for details in plan.values():
            self.assertIn("create_partitions", details)
            self.assertIn("detach_before", details)
