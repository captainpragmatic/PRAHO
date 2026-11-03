"""Existing shared tablespaces stay unsupported even after enabling file-per-table."""

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings
from django.test import SimpleTestCase


class QuotaDatabaseStorageTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho_quota_native.py"
        spec = importlib.util.spec_from_file_location("quota_database_storage", path)
        cls.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.native)

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.schema = self.root / "tenant"
        self.schema.mkdir()
        self.data = self.schema / "wp_posts.ibd"
        self.data.write_bytes(b"allocated tenant table")
        self.row = {
            "table": "wp_posts",
            "engine": "InnoDB",
            "space": 20,
            "space_type": "Single",
            "space_name": "tenant/wp_posts",
            "path": str(self.data),
        }

    def qualify(self, rows):
        return self.native.qualify_table_storage(
            self.schema,
            rows,
            gid=self.schema.stat().st_gid,
            device=self.schema.stat().st_dev,
        )

    def test_real_single_tablespace_file_is_required(self):
        self.qualify([self.row])
        for field, value in (
            ("space", 0),
            ("space", None),
            ("space", True),
            ("space_type", "System"),
            ("space_name", "other/wp_posts"),
            ("path", None),
            ("path", str(self.root / "ibdata1")),
            ("engine", "MyISAM"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.qualify([{**self.row, field: value}])

    def test_external_symlink_and_missing_datafiles_are_not_qualified(self):
        self.data.unlink()
        with self.assertRaises(ValueError):
            self.qualify([self.row])
        external = self.root / "external.ibd"
        external.write_bytes(b"not in the qualified tenant data directory")
        self.data.symlink_to(external)
        with self.assertRaises(ValueError):
            self.qualify([self.row])

    def test_foreign_group_and_filesystem_are_not_qualified(self):
        info = self.schema.stat()
        for gid, device in ((info.st_gid + 1, info.st_dev), (info.st_gid, info.st_dev + 1)):
            with self.subTest(gid=gid, device=device), self.assertRaises(ValueError):
                self.native.qualify_table_storage(self.schema, [self.row], gid=gid, device=device)
