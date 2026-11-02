"""Cross-component crashes never reopen an unowned or committed source."""

import importlib.util
import tempfile
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class ComponentSourceCoordinatorTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-source.py"
        spec = importlib.util.spec_from_file_location("component_source_coordinator", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve() / "receipts"
        self.operation, self.boot = str(uuid4()), str(uuid4())
        self.events, self.held = [], set()
        self.fail = None
        self.retained = "unchanged"
        outer = self

        class Fence:
            def __init__(self, name):
                self.name = name

            def apply(self):
                outer.events.append("apply:" + self.name)
                outer.held.add(self.name)
                if outer.fail == self.name:
                    raise RuntimeError("Lost response after native mutation")

            def verify(self):
                outer.events.append("verify:" + self.name)
                if self.name not in outer.held:
                    raise ValueError("Native hold is absent")

            def release(self):
                outer.events.append("release:" + self.name)
                outer.held.remove(self.name)

        self.steps = {name: Fence(name) for name in ("web", "cron", "database", "paths")}

    def coordinator(self, operation=None):
        return self.module.SourceCoordinator(
            "123456789",
            operation or self.operation,
            "a" * 64,
            preflight=lambda: {"retained_digest": self.retained, "scope": "exact native evidence"},
            build=lambda context: self.steps,
            retained=lambda context: self.retained,
            state_dir=self.directory,
            boot_id=self.boot,
        )

    def test_holds_all_components_before_export_and_compensates_in_reverse_order(self):
        coordinator = self.coordinator()
        coordinator.apply()
        coordinator.verify()
        self.assertEqual(self.held, set(self.steps))
        coordinator.release()
        self.assertFalse(self.held)
        self.assertEqual(
            [event for event in self.events if event.startswith("release:")],
            ["release:paths", "release:database", "release:cron", "release:web"],
        )
        coordinator.release()

    def test_lost_child_response_is_retried_under_the_same_durable_intent(self):
        coordinator = self.coordinator()
        self.fail = "database"
        with self.assertRaises(RuntimeError):
            coordinator.apply()
        state = coordinator.journal.read()
        self.assertEqual(state["pending"], "database")
        self.assertEqual(state["applied"], ["web", "cron"])
        self.assertNotIn("paths", self.held)
        self.fail = None
        self.coordinator().apply()
        self.assertEqual(self.held, set(self.steps))

    def test_compensation_includes_child_with_unacknowledged_mutation(self):
        coordinator = self.coordinator()
        self.fail = "database"
        with self.assertRaises(RuntimeError):
            coordinator.apply()
        coordinator.release()
        self.assertFalse(self.held)
        self.assertNotIn("release:paths", self.events)

    def test_retained_drift_and_other_attempt_cannot_authorize_export_or_release(self):
        coordinator = self.coordinator()
        coordinator.apply()
        with self.assertRaises(ValueError):
            self.coordinator(str(uuid4())).release()
        self.retained = "authentication or retained dependency changed"
        with self.assertRaises(ValueError):
            coordinator.verify()
        with self.assertRaises(ValueError):
            coordinator.release()
        self.assertEqual(self.held, set(self.steps))

    def test_committed_source_cannot_be_reopened_by_stale_compensation(self):
        coordinator = self.coordinator()
        coordinator.apply()
        coordinator.commit(archive_sha256="b" * 64, target_receipt_sha256="c" * 64)
        with self.assertRaises(ValueError):
            coordinator.release()
        with self.assertRaises(ValueError):
            coordinator.commit(archive_sha256="d" * 64, target_receipt_sha256="c" * 64)
        self.assertEqual(self.held, set(self.steps))

    def test_missing_child_hold_prevents_commit_receipt(self):
        coordinator = self.coordinator()
        coordinator.apply()
        self.held.remove("paths")
        with self.assertRaises(ValueError):
            coordinator.commit(archive_sha256="b" * 64, target_receipt_sha256="c" * 64)
        self.assertEqual(coordinator.journal.read()["phase"], "held")

    def test_new_attempt_requires_completed_compensation_of_previous_owner(self):
        coordinator = self.coordinator()
        coordinator.apply()
        replacement = self.coordinator(str(uuid4()))
        with self.assertRaises(ValueError):
            replacement.apply()
        coordinator.release()
        self.mark_artifacts_retired(coordinator)
        replacement.apply()
        self.assertEqual(self.held, set(self.steps))
        with self.assertRaises(ValueError):
            coordinator.release()

    def mark_artifacts_retired(self, coordinator):
        with coordinator.journal.locked():
            state = coordinator.journal.read()
            state["export_retirement"] = "retired"
            coordinator.journal.write(state)

    def test_replacement_cannot_erase_ready_export_ownership_before_artifacts_retire(self):
        coordinator = self.coordinator()
        coordinator.apply()
        with coordinator.journal.locked():
            state = coordinator.journal.read()
            state["export"] = {"phase": "ready", "path": "/private/owned-original-export"}
            coordinator.journal.write(state)
        coordinator.release()
        replacement = self.coordinator(str(uuid4()))
        with self.assertRaisesRegex(ValueError, "artifact|export|retir"):
            replacement.apply()
        self.assertEqual(coordinator.journal.read()["operation_id"], self.operation)
        self.assertEqual(coordinator.journal.read()["export"]["path"], "/private/owned-original-export")
        self.assertFalse(self.held)

    def test_delayed_old_uuid_cannot_refence_after_replacement_has_also_released(self):
        original = self.coordinator()
        original.apply()
        original.release()
        self.mark_artifacts_retired(original)
        replacement = self.coordinator(str(uuid4()))
        replacement.apply()
        replacement.release()
        self.mark_artifacts_retired(replacement)
        before = list(self.events)
        with self.assertRaisesRegex(ValueError, "history|seen|retir|old"):
            original.apply()
        self.assertEqual(self.events, before)
        self.assertFalse(self.held)

    def test_missing_or_unknown_current_history_never_authorizes_native_release(self):
        coordinator = self.coordinator()
        coordinator.apply()
        history = coordinator._operation_history(coordinator.journal.identity)
        original = history.path.read_bytes()
        history.path.unlink()
        with self.assertRaisesRegex(ValueError, "history"):
            coordinator.release()
        history.path.write_bytes(original)
        history.path.chmod(0o600)
        state = history.read()
        state["phase"] = "unknown"
        history.write(state)
        with self.assertRaisesRegex(ValueError, "history"):
            coordinator.verify()
        self.assertEqual(self.held, set(self.steps))

    def test_lost_parent_replacement_reply_keeps_old_uuid_tombstone_and_parks_uncertain_new_uuid(self):
        original = self.coordinator()
        original.apply()
        original.release()
        self.mark_artifacts_retired(original)
        replacement = self.coordinator(str(uuid4()))
        with (
            patch.object(replacement.journal, "create", side_effect=TimeoutError("Lost new parent receipt")),
            self.assertRaises(TimeoutError),
        ):
            replacement.apply()
        old_history = original._operation_history(original.journal.identity).read()
        self.assertEqual(old_history["phase"], "retired")
        self.assertNotIn("context", old_history)
        self.assertNotIn("exact native evidence", str(old_history))
        with self.assertRaises(ValueError):
            original.apply()
        with self.assertRaisesRegex(ValueError, "seen|history"):
            replacement.apply()
        self.assertFalse(self.held)

    def test_missing_history_for_released_parent_prevents_replacement_and_preserves_receipt(self):
        original = self.coordinator()
        original.apply()
        original.release()
        self.mark_artifacts_retired(original)
        original._operation_history(original.journal.identity).path.unlink()
        with self.assertRaisesRegex(ValueError, "history"):
            self.coordinator(str(uuid4())).apply()
        self.assertEqual(original.journal.read()["operation_id"], self.operation)

    def test_dangling_history_namespace_cannot_be_adopted_as_legacy_missing_history(self):
        coordinator = self.coordinator()
        coordinator.apply()
        with coordinator.journal.locked():
            state = coordinator.journal.read()
            state.pop("operation_history")
            coordinator.journal.write(state)
        history = coordinator._operation_history(coordinator.journal.identity)
        history.directory.rename(history.directory.with_suffix(".original"))
        history.directory.symlink_to(history.directory.parent / "missing-operation", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "namespace|history"):
            coordinator.release()
        self.assertEqual(self.held, set(self.steps))
