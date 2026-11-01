"""Native action dispatch cannot expose context, substitute archives or replay precommit work."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class ComponentSourceActionTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-action.py"
        spec = importlib.util.spec_from_file_location("component_source_action", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.operation = str(uuid4())
        self.source = SimpleNamespace(operation=self.operation, coordinator=MagicMock())
        self.source.coordinator._state.return_value = {"phase": "held"}
        self.native = SimpleNamespace(NativeSource=MagicMock(return_value=self.source))
        self.receipt = {"path": "/private/owned/archive", "sha256": "b" * 64, "bytes": 1234}
        self.exporter = SimpleNamespace(export_source=MagicMock(return_value=self.receipt))
        self.payload = {
            "request": {"domain_id": "123456789"},
            "operation_id": self.operation,
            "authority_digest": "a" * 64,
            "archive_sha256": "b" * 64,
            "target_receipt_sha256": "c" * 64,
        }

    def test_unrecognized_actions_never_construct_a_native_operation(self):
        with patch.object(self.module, "_module") as load, self.assertRaises(ValueError):
            self.module.perform({"action": "delete-domain"})
        load.assert_not_called()

    def test_export_returns_only_immutable_public_receipt(self):
        with patch.object(self.module, "_module", side_effect=[self.native, self.exporter]):
            result = self.module.perform({**self.payload, "action": "source_export"})
        self.assertEqual(
            result, {"operation_id": self.operation, "action": "source_export", "phase": "held", "export": self.receipt}
        )
        self.source.coordinator.commit.assert_not_called()

    def test_changed_archive_cannot_seal_compensation(self):
        self.payload["archive_sha256"] = "d" * 64
        with (
            patch.object(self.module, "_module", side_effect=[self.native, self.exporter]),
            self.assertRaises(ValueError),
        ):
            self.module.perform({**self.payload, "action": "source_commit"})
        self.source.coordinator.commit.assert_not_called()

    def test_released_export_cleanup_checks_exact_parent_without_reapplying_source_holds(self):
        cleanup = MagicMock(
            return_value={
                "phase": "released_export_retired",
                "operation_id": self.operation,
                "source_domain_id": self.payload["request"]["domain_id"],
            }
        )
        with patch.object(
            self.module, "_module", return_value=SimpleNamespace(cleanup_released_export=cleanup)
        ) as load:
            result = self.module.perform({**self.payload, "action": "source_retire_artifacts"})
        self.assertEqual(
            result, {"operation_id": self.operation, "action": "source_retire_artifacts", "phase": "artifacts_retired"}
        )
        cleanup.assert_called_once_with(self.payload["request"], self.operation, "a" * 64)
        load.assert_called_once_with("praho-component-retire.py", "component_action_retirement")

    def test_released_export_cleanup_refuses_a_different_native_parent_receipt(self):
        native = SimpleNamespace(
            cleanup_released_export=MagicMock(
                return_value={
                    "phase": "released_export_retired",
                    "operation_id": self.operation,
                    "source_domain_id": "987654321",
                }
            )
        )
        with patch.object(self.module, "_module", return_value=native), self.assertRaises(ValueError):
            self.module.perform({**self.payload, "action": "source_retire_artifacts"})

    def test_committed_retry_does_not_repeat_export_or_precommit_hold_checks(self):
        self.source.coordinator._state.return_value = {"phase": "committed"}
        with patch.object(self.module, "_module", return_value=self.native) as load:
            result = self.module.perform({**self.payload, "action": "source_commit"})
        self.assertEqual(result["phase"], "committed")
        load.assert_called_once()
        self.source.coordinator.commit.assert_called_once_with(archive_sha256="b" * 64, target_receipt_sha256="c" * 64)

    def test_explicit_target_actions_never_construct_a_source_operation(self):
        target = MagicMock()
        native = SimpleNamespace(
            TargetCoordinator=MagicMock(return_value=target),
            archives=SimpleNamespace(source=SimpleNamespace(authority_digest=lambda _manifest: "a" * 64)),
        )
        payload = {**self.payload, "target_identity": "d" * 64, "creation_params": {"domain": "example.test"}}
        for action, method in (
            ("target_prepare", "prepare"),
            ("target_restore", "restore"),
            ("target_verify", "verify"),
            ("target_retire_artifacts", "retire_artifacts"),
            ("target_retire_unprepared_archive", "retire_unprepared_archive"),
        ):
            with self.subTest(action=action), patch.object(self.module, "_module", return_value=native) as load:
                getattr(target, method).return_value = {"operation_id": self.operation, "phase": "held"}
                result = self.module.perform({**payload, "action": action})
                self.assertEqual(result, {"operation_id": self.operation, "phase": "held", "action": action})
                self.assertEqual(load.call_args.args[0], "praho-component-target.py")
                load.assert_called_once()
        with patch.object(self.module, "_module", return_value=native):
            target.activate.return_value = {"operation_id": self.operation, "phase": "active"}
            result = self.module.perform({**payload, "action": "target_activate", "enabled": False})
        self.assertEqual(result["phase"], "active")
        target.activate.assert_called_once_with("c" * 64, enabled=False)
