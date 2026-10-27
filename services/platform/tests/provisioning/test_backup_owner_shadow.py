"""Source capture must succeed under the caller lease before native backup dispatch."""

from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.test import SimpleTestCase

from apps.common.types import Ok
from apps.provisioning import virtualmin_backup_service as backup
from apps.provisioning.migration_target_hold import capture_backup_owner_shadow


class OwnerShadowBackupDispatchTests(SimpleTestCase):
    def setUp(self):
        self.service = object.__new__(backup.VirtualminBackupService)
        self.service.server = SimpleNamespace(hostname="node.example", node_deployment=object())
        self.service._owns_execution = Mock(return_value=True)
        self.service._read_domain_id = Mock(return_value=Ok("123"))
        self.service._update_backup_progress = Mock()
        self.service._backup_command_timeout = Mock(return_value=60)
        self.service._call_checked = Mock(return_value=Ok({}))
        self.account = SimpleNamespace(domain="customer.example", virtualmin_username="customer")
        self.metadata = {"archive_name": f"virtualmin_backup_{uuid4().hex}.tar.gz"}
        self.config = SimpleNamespace(
            chain_role=backup.CHAIN_ROLE_STANDALONE, **{flag: True for flag, _ in backup.BACKUP_COMPONENT_FEATURES}
        )

    def test_full_and_config_dispatch_capture_real_source_identity_before_backup(self):
        for method in ("_execute_full_backup", "_execute_config_backup"):
            events = []
            self.service._call_checked.side_effect = lambda *a, events=events: events.append("backup") or Ok({})
            with (
                patch(
                    "apps.provisioning.migration_target_hold.capture_backup_owner_shadow",
                    side_effect=lambda *a, events=events, **k: events.append("capture"),
                ) as capture,
                patch.object(backup, "VirtualminGateway"),
            ):
                result = getattr(self.service, method)(self.account, "backup-id", self.metadata, self.config)
            self.assertTrue(result.is_ok(), result)
            self.assertEqual(events, ["capture", "backup"])
            self.assertEqual(capture.call_args.kwargs["domain_id"], "123")
            self.assertEqual(capture.call_args.kwargs["archive_name"], self.metadata["archive_name"])
            self.assertEqual(self.metadata["owner_shadow_version"], 1)

    def test_capture_refusal_or_lost_lease_never_dispatches_backup(self):
        with (
            patch(
                "apps.provisioning.migration_target_hold.capture_backup_owner_shadow",
                side_effect=RuntimeError("reserved shadow flag unsupported"),
            ),
            patch.object(backup, "VirtualminGateway"),
        ):
            result = self.service._execute_full_backup(self.account, "backup-id", self.metadata, self.config)
        self.assertTrue(result.is_err())
        self.service._call_checked.assert_not_called()
        self.service._owns_execution.side_effect = [True, True, False]
        with (
            patch("apps.provisioning.migration_target_hold.capture_backup_owner_shadow"),
            patch.object(backup, "VirtualminGateway"),
        ):
            result = self.service._execute_full_backup(self.account, "backup-id", self.metadata, self.config)
        self.assertTrue(result.is_err())
        self.service._call_checked.assert_not_called()

    def test_api_only_server_is_refused_actionably_before_any_native_or_api_dispatch(self):
        self.service.server.node_deployment = None
        with patch("apps.provisioning.migration_target_hold.capture_backup_owner_shadow") as capture:
            result = self.service._execute_full_backup(self.account, "backup-id", self.metadata, self.config)
        self.assertTrue(result.is_err())
        self.assertIn("enroll the API-only server", result.unwrap_err())
        self.service._read_domain_id.assert_not_called()
        self.service._call_checked.assert_not_called()
        capture.assert_not_called()

    def test_source_identity_read_cannot_dispatch_capture_after_ownership_expires(self):
        self.service._owns_execution.side_effect = [True, False]
        with patch("apps.provisioning.migration_target_hold.capture_backup_owner_shadow") as capture:
            result = self.service._execute_full_backup(self.account, "backup-id", self.metadata, self.config)
        self.assertTrue(result.is_err())
        capture.assert_not_called()
        self.service._call_checked.assert_not_called()

    def test_unsupported_reserved_shadow_flag_is_an_actionable_capture_refusal(self):
        with patch("apps.infrastructure.ansible_service.AnsibleService") as service:
            service.return_value.run_playbook.return_value = Ok(
                SimpleNamespace(success=False, stdout="PRAHO_OWNER_SHADOW_RESERVED_FLAG")
            )
            with self.assertRaisesRegex(RuntimeError, "reserved flag.*unsupported"):
                capture_backup_owner_shadow(
                    self.service.server,
                    domain=self.account.domain,
                    owner=self.account.virtualmin_username,
                    domain_id="123",
                    archive_name=self.metadata["archive_name"],
                    operation_id=uuid4(),
                )
