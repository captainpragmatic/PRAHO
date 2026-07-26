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

from apps.common.types import Err, Ok
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
    def test_component_failure_marks_restore_progress_failed(
        self, _mock_config_cls: MagicMock, _mock_gateway_cls: MagicMock
    ) -> None:
        """An operator polling progress must see 'failed', not a stuck intermediate phase."""
        with (
            patch.object(
                self.service,
                "_prepare_restore_session",
                return_value=Ok(("/var/backups/praho/backup.tar", {"meta": True}, {"rollback": True})),
            ),
            patch.object(self.service, "_execute_restore_components", return_value=["Files restore failed"]),
            patch.object(self.service, "_execute_restore_rollback", return_value=Ok(None)),
            patch.object(self.service, "_update_restore_progress") as mock_progress,
            patch.object(self.service, "_generate_restore_id", return_value="rs-fail"),
        ):
            self.service.restore_domain(self.account, self.config)

        phases = [call.args[1] for call in mock_progress.call_args_list if len(call.args) > 1]
        self.assertIn("failed", phases, f"progress must reach 'failed', got {phases}")

    @patch("apps.provisioning.virtualmin_backup_service.VirtualminGateway")
    @patch("apps.provisioning.virtualmin_backup_service.VirtualminConfig")
    def test_rollback_failure_is_surfaced_in_the_error(
        self, _mock_config_cls: MagicMock, _mock_gateway_cls: MagicMock
    ) -> None:
        """A failed rollback after a failed restore leaves the account in an unknown
        state — the operator must be told, not left with only the component errors."""
        with (
            patch.object(
                self.service,
                "_prepare_restore_session",
                return_value=Ok(("/var/backups/praho/backup.tar", {"meta": True}, {"rollback": True})),
            ),
            patch.object(self.service, "_execute_restore_components", return_value=["Database restore failed"]),
            patch.object(
                self.service,
                "_execute_restore_rollback",
                return_value=Err("rollback could not reach the server"),
            ),
            patch.object(self.service, "_update_restore_progress"),
            patch.object(self.service, "_generate_restore_id", return_value="rs-rbfail"),
        ):
            result = self.service.restore_domain(self.account, self.config)

        self.assertTrue(result.is_err())
        err = result.unwrap_err().lower()
        self.assertIn("rollback", err, f"a failed rollback must be surfaced, got: {result.unwrap_err()}")

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
            patch.object(
                self.service, "_finalize_restore_operation", return_value=Ok({"restored": True})
            ) as mock_finalize,
            patch.object(self.service, "_update_restore_progress"),
            patch.object(self.service, "_generate_restore_id", return_value="rs-2"),
        ):
            result = self.service.restore_domain(self.account, self.config)

        self.assertTrue(result.is_ok())
        mock_finalize.assert_called_once()
        mock_rollback.assert_not_called()


class FinalizeIntegrityFailureTests(TestCase):
    """_finalize_restore_operation must also fail closed on a failed rollback."""

    def setUp(self) -> None:
        self.server = MagicMock()
        self.server.hostname = "vm.example.com"
        self.service = VirtualminBackupService(self.server)
        self.account = MagicMock()
        self.account.domain = "example.com"

    def _params(self) -> dict:
        from apps.provisioning.virtualmin_backup_service import RestoreOperationParams  # noqa: PLC0415

        return RestoreOperationParams(
            gateway=MagicMock(),
            account=self.account,
            backup_metadata={"meta": True},
            restore_id="rs-final",
            config=RestoreConfig(backup_id="bk-1"),
            rollback_data={"rollback": True},
        )

    def test_integrity_failure_with_failed_rollback_is_surfaced(self) -> None:
        """A post-restore integrity failure whose rollback also fails must report both,
        mark progress failed, and never claim success."""
        with (
            patch.object(self.service, "_verify_restore_integrity", return_value=Err("integrity mismatch")),
            patch.object(self.service, "_execute_restore_rollback", return_value=Err("rollback unreachable")),
            patch.object(self.service, "_update_restore_progress") as mock_progress,
        ):
            result = self.service._finalize_restore_operation(self._params())

        self.assertTrue(result.is_err())
        err = result.unwrap_err().lower()
        self.assertIn("integrity", err)
        self.assertIn("rollback", err)
        phases = [call.args[1] for call in mock_progress.call_args_list if len(call.args) > 1]
        self.assertIn("failed", phases, f"progress must reach 'failed', got {phases}")
