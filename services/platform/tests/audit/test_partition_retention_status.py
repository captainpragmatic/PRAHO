from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase

from apps.audit.services import AuditRetentionService


class TestPartitionRetentionStatus(TestCase):
    @patch("apps.common.partitioning.EventPartitionService")
    def test_retention_status_includes_partition_tables(self, mock_partition_service_cls) -> None:
        mock_partition_service = mock_partition_service_cls.return_value
        mock_partition_service.get_status.return_value = {
            "audit_events": {
                "status": "not_partitioned",
                "archive_retention_days": 2555,
                "attached_partitions": [],
            },
        }

        status = AuditRetentionService.get_retention_status()

        self.assertIn("table:audit_events", status)
        self.assertEqual(status["table:audit_events"]["action"], "partition_rotation")
        self.assertEqual(status["table:audit_events"]["retention_days"], 2555)
        self.assertEqual(status["table:audit_events"]["compliance_status"], "action_required")

    @patch("apps.common.partitioning.EventPartitionService")
    def test_retention_status_partitioned_is_compliant(self, mock_partition_service_cls) -> None:
        mock_partition_service = mock_partition_service_cls.return_value
        mock_partition_service.get_status.return_value = {
            "audit_events": {
                "status": "partitioned",
                "archive_retention_days": 2555,
                "attached_partitions": ["p2026_01"],
            },
        }

        status = AuditRetentionService.get_retention_status()

        self.assertEqual(status["table:audit_events"]["compliance_status"], "compliant")
