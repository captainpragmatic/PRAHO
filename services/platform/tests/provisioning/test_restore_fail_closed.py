"""#326: restore_domain must fail closed when component restores fail.

Previously restore_domain collected the per-component error list from
_execute_restore_components and then called _finalize_restore_operation
unconditionally, so a partial or total restore failure still reported
"Restore completed successfully". Component failures must now roll back
and surface as an error instead of a fictional success.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Ok
from apps.provisioning.virtualmin_backup_service import RestoreConfig, VirtualminBackupService


class RestoreFailClosedTests(TestCase):
    """restore_domain surfaces component failures instead of finalizing as success."""

    def setUp(self) -> None:
        self.server = MagicMock()
        self.server.hostname = "vm.example.com"
        self.service = VirtualminBackupService(self.server)
        self.account = MagicMock()
        self.account.domain = "example.com"
        self.config = RestoreConfig(backup_id="bk-1")

    @patch("apps.provisioning.virtualmin_backup_service.VirtualminGateway")
    @patch("apps.provisioning.virtualmin_backup_service.VirtualminConfig")
    def test_component_errors_roll_back_and_return_err(
        self, _mock_config_cls: MagicMock, _mock_gateway_cls: MagicMock
    ) -> None:
        """When a component restore fails, restore_domain rolls back and returns Err."""
        with (
            patch.object(
                self.service,
                "_prepare_restore_session",
                return_value=Ok(("/var/backups/praho/backup.tar", {"meta": True}, {"rollback": True})),
            ),
            patch.object(
                self.service,
                "_execute_restore_components",
                return_value=["Database restore failed: connection refused"],
            ),
            patch.object(self.service, "_execute_restore_rollback") as mock_rollback,
            patch.object(self.service, "_finalize_restore_operation") as mock_finalize,
            patch.object(self.service, "_update_restore_progress"),
            patch.object(self.service, "_generate_restore_id", return_value="rs-1"),
        ):
            result = self.service.restore_domain(self.account, self.config)

        self.assertTrue(result.is_err())
        self.assertIn("component error", result.unwrap_err().lower())
        mock_rollback.assert_called_once()
        # A failed restore must NOT be finalized as success.
        mock_finalize.assert_not_called()

    @patch("apps.provisioning.virtualmin_backup_service.VirtualminGateway")
    @patch("apps.provisioning.virtualmin_backup_service.VirtualminConfig")
    def test_no_component_errors_finalizes_normally(
        self, _mock_config_cls: MagicMock, _mock_gateway_cls: MagicMock
    ) -> None:
        """Non-regression: with no component errors the restore finalizes as before."""
        with (
            patch.object(
                self.service,
                "_prepare_restore_session",
                return_value=Ok(("/var/backups/praho/backup.tar", {"meta": True}, {"rollback": True})),
            ),
            patch.object(self.service, "_execute_restore_components", return_value=[]),
            patch.object(self.service, "_execute_restore_rollback") as mock_rollback,
            patch.object(self.service, "_finalize_restore_operation", return_value=Ok({"restored": True})) as mock_finalize,
            patch.object(self.service, "_update_restore_progress"),
            patch.object(self.service, "_generate_restore_id", return_value="rs-2"),
        ):
            result = self.service.restore_domain(self.account, self.config)

        self.assertTrue(result.is_ok())
        mock_finalize.assert_called_once()
        mock_rollback.assert_not_called()
