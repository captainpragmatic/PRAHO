from __future__ import annotations

from datetime import datetime
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import SimpleTestCase
from django.utils import timezone

from apps.common.partitioning import EventPartitionService


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
