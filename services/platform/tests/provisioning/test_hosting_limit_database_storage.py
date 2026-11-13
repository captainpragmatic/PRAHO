"""Database storage stays out of the kernel quota: MariaDB owns every file; shared tablespaces stay unsupported."""

import importlib.util
import os
import stat
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

    def test_a_leftover_backup_dump_is_seen_without_following_links(self):
        home = self.root / "home"
        home.mkdir()
        self.assertFalse(self.native._backup_staging_left(home))
        (home / ".backup").mkdir()
        self.assertTrue(self.native._backup_staging_left(home))
        (home / ".backup").rmdir()
        (home / ".backup").symlink_to(self.root / "absent-target")
        self.assertTrue(self.native._backup_staging_left(home))  # A dangling link the tenant planted still counts.

    def test_every_probe_reports_whether_a_backup_dump_was_left(self):
        source = (Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho_quota_native.py").read_text()
        probe = source[source.index("    def _probe(") : source.index("    def apply(")]
        self.assertIn('"backup_staging_left": _backup_staging_left(Path(account.pw_dir))', probe)

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
            uid=self.schema.stat().st_uid,
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

    def test_a_layout_a_repair_cannot_fix_is_refused_and_named(self):
        for field, value in (("engine", "MyISAM"), ("space_type", "System")):
            with (
                self.subTest(field=field),
                patch.object(self.native, "_table_inventory", return_value=[{**self.row, field: value}]),
                self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "Database tenant"),
            ):
                self.native.repairable_database_layout(self.schema)

    def test_external_symlink_and_missing_datafiles_are_not_qualified(self):
        self.data.unlink()
        with self.assertRaises(ValueError):
            self.qualify([self.row])
        external = self.root / "external.ibd"
        external.write_bytes(b"not in the qualified tenant data directory")
        self.data.symlink_to(external)
        with self.assertRaises(ValueError):
            self.qualify([self.row])

    def test_foreign_owner_group_and_filesystem_are_not_qualified(self):
        info = self.schema.stat()
        for uid, gid, device in (
            (info.st_uid + 1, info.st_gid, info.st_dev),
            (info.st_uid, info.st_gid + 1, info.st_dev),
            (info.st_uid, info.st_gid, info.st_dev + 1),
        ):
            with self.subTest(uid=uid, gid=gid, device=device), self.assertRaises(ValueError):
                self.native.qualify_table_storage(self.schema, [self.row], uid=uid, gid=gid, device=device)

    # Stat results are doubled so ownership cases don't depend on the runner's groups or on running as root.
    MARIADB = (110, 113)
    TENANT = (1001, 1001)

    def qualify_directory(self, **attributes):
        """attributes: {path: {"uid": .., "gid": .., "mode": ..}}, applied over a clean mysql:mysql tree."""
        real_lstat = os.lstat
        offsets = {"mode": stat.ST_MODE, "uid": stat.ST_UID, "gid": stat.ST_GID}

        def doubled(path):
            fields = list(real_lstat(path))
            fields[stat.ST_UID], fields[stat.ST_GID] = self.MARIADB
            fields[stat.ST_MODE] &= ~stat.S_ISGID
            for key, value in attributes.get(Path(path).name, {}).items():
                fields[offsets[key]] = value
            return os.stat_result(fields)

        with patch.object(Path, "lstat", lambda path: doubled(path)):  # noqa: PLW0108 -- Binds as a Path method.
            self.native.qualify_database_directory(
                self.schema, writer=self.MARIADB, tenant=self.TENANT, device=real_lstat(self.schema).st_dev
            )

    def test_mariadb_owned_directory_and_files_are_qualified(self):
        self.qualify_directory()

    def test_a_tenant_charged_directory_is_refused_and_named(self):
        for name, attributes in (
            ("group", {"gid": self.TENANT[1]}),
            ("owner", {"uid": self.TENANT[0]}),
            ("setgid", {"mode": stat.S_IFDIR | stat.S_ISGID | 0o750}),
            ("world-writable", {"mode": stat.S_IFDIR | 0o777}),
        ):
            with (
                self.subTest(name),
                self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "Database tenant.*directory"),
            ):
                self.qualify_directory(tenant=attributes)

    def test_one_tenant_charged_file_under_a_correct_directory_is_refused_and_named(self):
        for name, attributes in (("group", {"gid": self.TENANT[1]}), ("owner", {"uid": self.TENANT[0]})):
            with (
                self.subTest(name),
                self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "Database tenant.*wp_posts.ibd"),
            ):
                self.qualify_directory(**{"wp_posts.ibd": attributes})

    def test_a_non_regular_entry_is_refused(self):
        (self.schema / "linked.ibd").symlink_to(self.data)
        with self.assertRaises(self.native.DatabaseStorageRefusalError):
            self.qualify_directory()

    def test_a_tenant_sharing_mariadbs_identity_is_refused(self):
        for tenant in ((self.MARIADB[0], 1001), (1001, self.MARIADB[1])):
            with self.subTest(tenant=tenant), self.assertRaises(self.native.DatabaseStorageRefusalError):
                self.native.qualify_database_directory(
                    self.schema, writer=self.MARIADB, tenant=tenant, device=self.schema.stat().st_dev
                )

    def writer_status(self, capabilities="0", uids="110\t110\t110\t110", gids="113\t113\t113\t113", bounding=""):
        status = self.root / "status"
        status.write_text(f"Uid:\t{uids}\nGid:\t{gids}\nCapEff:\t{capabilities}\n")
        real_open = os.open
        answers = iter(["4242", bounding])
        with (
            patch.object(self.native, "_run", side_effect=lambda *_args, **_kwargs: next(answers)),
            patch.object(self.native.os, "open", lambda _path, flags: real_open(status, flags)),
        ):
            return self.native._database_writer_qualified()

    def test_the_writer_identity_comes_from_the_running_server(self):
        self.assertEqual(self.writer_status(), (110, 113))

    def test_a_writer_with_resource_override_is_still_refused_as_least_privilege(self):
        capable = f"{1 << self.native.CAP_SYS_RESOURCE:x}"
        for arguments in ({"capabilities": capable}, {"bounding": "cap_chown cap_sys_resource"}):
            with self.subTest(arguments), self.assertRaisesRegex(ValueError, "least privilege"):
                self.writer_status(**arguments)

    def test_a_root_writer_is_refused(self):
        for arguments in ({"uids": "0\t0\t0\t0"}, {"gids": "0\t0\t0\t0"}):
            with self.subTest(arguments), self.assertRaises(ValueError):
                self.writer_status(**arguments)
