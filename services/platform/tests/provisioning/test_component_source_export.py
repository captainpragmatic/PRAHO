"""Uncertain native exports preserve private artifacts and cannot replay writes."""

import hashlib
import importlib.util
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class ComponentSourceExportTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helpers = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"
        for attribute, filename in (
            ("module", "praho-component-source-export.py"),
            ("coordination", "praho-component-source.py"),
        ):
            spec = importlib.util.spec_from_file_location("export_contract_" + attribute, helpers / filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            setattr(cls, attribute, module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.operation = str(uuid4())
        self.steps = {name: MagicMock() for name in self.coordination.ORDER}
        context = {"retained_digest": "a" * 64, "manifest": {"paths": [], "databases": []}}
        coordinator = self.coordination.SourceCoordinator(
            "123456789",
            self.operation,
            "b" * 64,
            preflight=lambda: context,
            build=lambda _context: self.steps,
            retained=lambda _context: "a" * 64,
            state_dir=self.directory / "receipts",
            boot_id=str(uuid4()),
        )
        self.source = SimpleNamespace(operation=self.operation, coordinator=coordinator, request={})
        self.staging = self.directory / "staging"
        self.enterContext(patch.object(self.module, "ROOT", self.staging))
        self.capacity = MagicMock()
        inspector = SimpleNamespace(capacity=self.capacity, native_temporary_directory=lambda: self.directory / "native")
        self.enterContext(patch.object(self.module, "_module", return_value=inspector))

    def test_no_export_is_dispatched_without_all_durable_holds(self):
        with patch.object(self.module, "_run") as run, self.assertRaises(ValueError):
            self.module.export_source(self.source)
        run.assert_not_called()
        self.assertFalse(self.staging.exists())

    def test_lost_native_capture_response_parks_the_same_export_without_replay(self):
        self.source.request = {"domain": "example.test", "domain_id": "123456789", "owner": "customer"}
        self.source.coordinator.apply()
        with patch.object(self.module, "_run", side_effect=TimeoutError("Lost remote response")) as run:
            with self.assertRaises(TimeoutError):
                self.module.export_source(self.source)
            with self.assertRaisesRegex(ValueError, "incomplete"):
                self.module.export_source(self.source)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(self.source.coordinator.journal.read()["export"]["phase"], "started")
        self.source.coordinator.verify()
        for step in self.steps.values():
            step.release.assert_not_called()

    def test_durable_export_receipt_is_rehashed_and_never_reruns_backup(self):
        self.source.coordinator.apply()
        directory = self.staging / self.operation
        directory.mkdir(parents=True, mode=0o700)
        path = directory / ("migration_" + self.operation + ".tar.gz")
        path.write_bytes(b"immutable private selected native archive")
        path.chmod(0o600)
        receipt = {
            "path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }
        with self.source.coordinator.journal.locked():
            state = self.source.coordinator.journal.read()
            state["export"] = {"phase": "ready", **receipt}
            self.source.coordinator.journal.write(state)
        with patch.object(self.module, "_run") as run:
            self.assertEqual(self.module.export_source(self.source), receipt)
            path.write_bytes(b"changed after publication")
            with self.assertRaisesRegex(ValueError, "changed"):
                self.module.export_source(self.source)
        run.assert_not_called()
