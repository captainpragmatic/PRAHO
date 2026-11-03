"""Existing shared tablespaces stay unsupported even after enabling file-per-table."""

import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

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

    def test_only_local_native_absent_or_empty_bandwidth_is_unlimited(self):
        self.assertEqual(self.native._configured_bandwidth({}), 0)
        self.assertEqual(self.native._configured_bandwidth({"bw_limit": ""}), 0)
        self.assertEqual(self.native._configured_bandwidth({"bw_limit": "0"}), 0)
        self.assertEqual(self.native._configured_bandwidth({"bw_limit": "1048576"}), 1048576)
        with self.assertRaises(ValueError):
            self.native._configured_bandwidth({"bw_limit": "unknown"})
        for key in ("quota", "uquota"):
            self.assertEqual(self.native._configured_limit({}, key), 0)
            self.assertEqual(self.native._configured_limit({key: ""}, key), 0)
            with self.assertRaises(ValueError):
                self.native._configured_limit({key: "unknown"}, key)

    def test_probe_budget_stops_before_spawning_another_native_command(self):
        token = self.native._PROBE_DEADLINE.set(10.0)
        self.addCleanup(self.native._PROBE_DEADLINE.reset, token)
        with (
            patch.object(self.native.time, "monotonic", return_value=11.0),
            patch.object(
                self.native.subprocess,
                "run",
            ) as runner,
            self.assertRaises(TimeoutError),
        ):
            self.native._run(["/usr/bin/true"])
        runner.assert_not_called()

    def test_bandwidth_safety_reads_actual_global_and_domain_controls(self):
        domain = {"bw_no_disable": "1"}
        self.assertTrue(self.native._bandwidth_actions_safe(domain, {}))
        self.assertTrue(self.native._bandwidth_actions_safe(domain, {"bw_disable": "0", "bw_enable": ""}))
        for key in ("bw_disable", "bw_enable"):
            for value in ("1", "false", "00"):
                with self.subTest(key=key, value=value):
                    self.assertFalse(self.native._bandwidth_actions_safe(domain, {key: value}))
        for value in (None, "", "0"):
            self.assertFalse(self.native._bandwidth_actions_safe({"bw_no_disable": value}, {}))

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
