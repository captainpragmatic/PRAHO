"""Temporary selected exports must leave capacity for retained source services."""

import importlib.util
import io
import tempfile
from pathlib import Path
from types import SimpleNamespace

from django.conf import settings
from django.test import SimpleTestCase


class ComponentExportCapacityTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-capacity.py"
        spec = importlib.util.spec_from_file_location("component_export_capacity", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_selected_files_sql_growth_and_retained_reserve_cover_both_native_workspaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            selected = {"paths": [{"bytes": 100}], "databases": [{"bytes": 200}]}
            required = self.module.required_bytes(selected)
            self.assertGreater(required, 300 + self.module.RETAINED_RESERVE_BYTES)
            staging, native_temp = root / "exports", root / "native"
            native_temp.mkdir()
            calls = []

            def enough(path):
                calls.append(path)
                return SimpleNamespace(free=required)

            self.module.require_capacity(selected, staging, native_temp, usage=enough)
            self.assertEqual(calls, [root, native_temp])

            def low_native(path):
                return SimpleNamespace(free=required - 1 if path == native_temp else required)

            with self.assertRaisesRegex(ValueError, "temporary"):
                self.module.require_capacity(selected, staging, native_temp, usage=low_native)
            self.assertFalse(staging.exists(), "Read-only capacity qualification created source staging")

    def test_space_qualification_rejects_symlinked_staging_and_negative_selected_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                self.module.require_capacity({"paths": [], "databases": []}, alias / "exports", root)
        with self.assertRaises(ValueError):
            self.module.required_bytes({"paths": [{"bytes": -1}], "databases": []})

    def test_shared_dump_budget_counts_all_selected_outputs_and_never_writes_rejected_chunk(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            budget = self.module.OutputBudget(5, (directory,), reserve_bytes=0)
            first, second = io.BytesIO(), io.BytesIO()
            budget.writer(first).write(b"123")
            with self.assertRaisesRegex(ValueError, "budget"):
                budget.writer(second).write(b"456")
            self.assertEqual(first.getvalue(), b"123")
            self.assertEqual(second.getvalue(), b"")
            self.assertEqual(budget.written, 3)

    def test_admission_includes_all_hard_capped_native_and_sql_working_copies(self):
        manifest = {"paths": [{"bytes": 12345}], "databases": [{"bytes": 54321}]}
        self.assertEqual(
            self.module.required_bytes(manifest),
            4 * self.module.native_archive_budget(manifest)
            + 4 * self.module.sql_dump_budget(manifest)
            + self.module.RETAINED_RESERVE_BYTES,
        )
