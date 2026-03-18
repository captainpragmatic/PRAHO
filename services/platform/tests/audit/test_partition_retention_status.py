from __future__ import annotations

from unittest.mock import patch

from django.test import SimpleTestCase

from apps.audit.compliance import LogRetentionService


class TestPartitionRetentionStatus(SimpleTestCase):
    @patch("apps.audit.compliance.EventPartitionService")
    def test_retention_status_includes_partition_tables(self, mock_partition_service_cls) -> None:
        mock_partition_service = mock_partition_service_cls.return_value
        mock_partition_service.get_status.return_value = {
            "audit_events": {
                "status": "not_partitioned",
                "archive_retention_days": 2555,
                "attached_partitions": [],
            },
        }

        service = LogRetentionService()
        service.retention_config = {}
        status = service.get_retention_status()

        self.assertIn("table:audit_events", status)
        self.assertEqual(status["table:audit_events"]["action"], "partition_rotation")
        self.assertEqual(status["table:audit_events"]["retention_days"], 2555)
        self.assertEqual(status["table:audit_events"]["compliance_status"], "action_required")
