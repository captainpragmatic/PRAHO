"""Selected dumps and private credentials require a complete, still-held SQL fence."""

import importlib.util
import io
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

from tests.provisioning.test_component_database_fence import FenceSQLFixture


class ComponentDatabaseExportTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-database-export.py"
        spec = importlib.util.spec_from_file_location("component_database_export", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.sql = FenceSQLFixture()
        self.sql.secret = "*" + "A" * 40
        self.operation = str(uuid4())
        self.exported = []

    def fence(self):
        return self.module.fences.DatabaseFence(
            "123456789",
            self.operation,
            self.module.fences.mysql.inspect_databases(("customer_web",), ("customer_web",), execute=self.sql)[
                "databases"
            ],
            ("customer_web",),
            state_dir=self.root / "receipts",
            boot_id=str(uuid4()),
            execute=self.sql,
        )

    def dump(self, database, stream):
        self.exported.append(database)
        stream.write(b"-- selected native database\nCREATE TABLE selected_fixture (id INT);\n")

    def test_exact_selected_dumps_are_private_and_credentials_do_not_enter_receipts(self):
        fence = self.fence()
        fence.apply()
        result = self.module.export_databases(fence, self.root, dump=self.dump)
        self.assertEqual(self.exported, ["customer_web"])
        self.assertEqual(set(result["dumps"]), {"customer_web"})
        path = result["dumps"]["customer_web"]
        self.assertEqual(path.parent, self.root)
        self.assertIn(self.operation, path.name)
        self.assertIn(b"selected_fixture", path.read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            [(row["user"], row["host"], row["authentication_string"]) for row in result["principals"]],
            [("webapp", "localhost", self.sql.secret)],
        )
        self.assertNotIn(self.sql.secret, fence.journal.path.read_text())
        self.assertTrue(self.sql.locked)
        fence.verify()

    def test_unheld_or_changed_native_scope_refuses_before_dump(self):
        fence = self.fence()
        with self.assertRaises(ValueError):
            self.module.export_databases(fence, self.root, dump=self.dump)
        self.assertEqual(self.exported, [])
        fence.apply()
        self.sql.shared = True
        with self.assertRaises(ValueError):
            self.module.export_databases(fence, self.root, dump=self.dump)
        self.assertEqual(self.exported, [])

    def test_a_lost_dump_result_is_private_and_cannot_be_silently_overwritten(self):
        fence = self.fence()
        fence.apply()

        def incomplete(database, stream):
            self.dump(database, stream)
            raise OSError("Lost native dump response")

        with self.assertRaises(OSError):
            self.module.export_databases(fence, self.root, dump=incomplete)
        files = list(self.root.glob("*.sql"))
        self.assertEqual(len(files), 1)
        before = files[0].read_bytes()
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.module.export_databases(fence, self.root, dump=self.dump)
        self.assertEqual(files[0].read_bytes(), before)

    def test_compressed_schema_expansion_is_aborted_before_writing_over_approved_budget(self):
        budget = self.module.capacity.OutputBudget(1024, (self.root,), reserve_bytes=0)
        stream = io.BytesIO()
        processes = []
        native_popen = subprocess.Popen

        def expanding(_arguments, **kwargs):
            process = native_popen([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*1048576)"], **kwargs)
            processes.append(process)
            return process

        with (
            patch.object(self.module.subprocess, "Popen", side_effect=expanding),
            self.assertRaisesRegex(ValueError, "budget"),
        ):
            self.module.native_dump("customer_web", budget.writer(stream))
        self.assertLessEqual(len(stream.getvalue()), 1024)
        self.assertIsNotNone(processes[0].poll(), "The unbounded native dump process was left running")

    def test_low_current_free_space_preserves_retained_reserve_and_private_partial_dump(self):
        fence = self.fence()
        fence.apply()
        free = SimpleNamespace(free=1027)
        budget = self.module.capacity.OutputBudget(1000, (self.root,), reserve_bytes=1024, usage=lambda _path: free)
        with self.assertRaisesRegex(ValueError, "reserve"):
            self.module.export_databases(fence, self.root, dump=self.dump, budget=budget)
        path = next(self.root.glob("*.sql"))
        self.assertEqual(path.stat().st_size, 0)
        self.assertTrue(self.sql.locked)
        fence.verify()
        with self.assertRaises(FileExistsError):
            self.module.export_databases(fence, self.root, dump=self.dump, budget=budget)
