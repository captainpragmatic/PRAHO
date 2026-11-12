"""Acceptance decisions with SQL/OS boundaries doubled, never physical quota proof."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Lock
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from django.conf import settings
from django.test import SimpleTestCase


class DatabaseBoundary:
    """In-memory transactional SQL boundary; the acceptance/thread algorithm stays real."""

    def __init__(self, module, *, diagnostic=None, commit_error=False, commit_persists=True):
        self.module = module
        self.diagnostic = diagnostic
        self.commit_error = commit_error
        self.commit_persists = commit_persists
        self.ready, self.denied = Event(), Event()
        self.lock = Lock()
        self.neighbor_rows = 0
        self.fill_rows = 0
        self.markers = set()
        self.transactions = []
        self.count_reads = []
        self.marker_reads = []
        self.statements = []
        self.probe_calls = 0
        self.pid_reads = 0
        self.changed_pid = False
        self.changed_pid_after_commit = False
        self.failed_qualification_after_commit = False
        self.used_bytes = module.LIMIT_KIB * 1024
        self.used_after_inserts = None
        self.database_bytes = (module.MAX_INSERTS + 1) * 1024 * 1024
        self.disk_temporary_tables = 2
        self.tmpdir = "/tmp\t"  # noqa: S108 -- Echoes the managed server's real setting; nothing is created there.
        self.mariadb_hard_kib = 0
        self.native = ModuleType("praho_quota_native")
        self.native._database_writer_qualified = Mock(side_effect=self.qualify_writer)
        self.native._kernel_quota = Mock(side_effect=lambda *_a, **_k: SimpleNamespace(hard=self.mariadb_hard_kib))
        self.native._set_kernel_quota = Mock()
        self.native._run = self.read_native
        self.file_writes = Mock()
        self.commands = []
        self.dump_bytes = module.LIMIT_KIB * 1024 + 1
        self.backup_exits = {"full": 0, "small": 1}
        self.restore_exit = 0
        self.leftover_after = set()
        self.caps_lifted_after = set()
        self.rows_after_restore = None
        self.phase = None

    def read_native(self, arguments):
        if arguments[0] == "/usr/bin/systemctl":
            self.pid_reads += 1
            changed = (self.changed_pid and self.pid_reads > 1) or (self.changed_pid_after_commit and self.markers)
            return "999" if changed else "777"
        assert arguments[0] == "/usr/bin/findmnt"
        return json.dumps({"filesystems": [{"source": "/dev/owned-fixture-only"}]})

    def qualify_writer(self):
        if self.failed_qualification_after_commit and self.markers:
            raise AssertionError("Post-denial writer qualification refused")
        return (110, 113)

    def domain(self, name):
        assert name in {"victim", "neighbor"}
        user = "q77612345678" + ("n" if name == "neighbor" else "")
        return {"user": user, "gid": "1001", "home": "/home/" + user}

    def native_command(self, argv, *, timeout=120, allow_error=False, payload=None):
        self.commands.append(argv)
        program = argv[0].rsplit("/", 1)[-1]
        returncode, stdout = 0, ""
        if program == "virtualmin" and argv[1] == "backup-domain":
            destination = argv[argv.index("--dest") + 1]
            self.phase = "small" if "small" in destination else "full"
            returncode = self.backup_exits[self.phase]
        elif program == "virtualmin" and argv[1] == "restore-domain":
            self.phase = "restore"
            returncode = self.restore_exit
            if self.rows_after_restore is not None:
                self.fill_rows = self.rows_after_restore
        elif program == "tar":
            name = ".backup/q77612345678.example.invalid_mysql_q77612345678_quota"
            stdout = f"-rw------- q776/q776 {self.dump_bytes} 2026-11-12 18:00 {name}\n"
        elif program == "findmnt":
            returncode = 1
        elif program != "journalctl":
            assert program in {"mount", "umount", "rm"}, argv
        if returncode and not allow_error:
            raise AssertionError("Native fixture operation failed: " + " ".join(argv[:2]))
        return self.result("native", stdout=stdout, returncode=returncode)

    def leftover(self, _domain):
        return self.phase in self.leftover_after

    def probe(self, _domain):
        self.probe_calls += 1
        if self.phase in self.caps_lifted_after:
            raise AssertionError("Normal native create/reboot/update did not retain equal hard UID/GID caps")
        used = self.used_bytes
        if self.used_after_inserts is not None and self.fill_rows:
            used = self.used_after_inserts
        database = self.database_bytes if self.fill_rows else 0
        return {"gid_used_bytes": used, "observation": {"database_bytes": database}}

    @staticmethod
    def result(query, *, stdout="", returncode=0, stderr=""):
        return subprocess.CompletedProcess(["mariadb", query], returncode, stdout, stderr)

    def sql(self, query, *, allow_error=False):  # noqa: C901, PLR0911, PLR0912 -- One closed fixture boundary.
        self.statements.append(query)
        if query.startswith("INSERT INTO `q77612345678_quota`.quota_fill"):
            assert allow_error
            assert self.ready.wait(2), "Concurrent neighbor never committed its required baseline"
            if self.diagnostic is not None:
                return self.result(query, returncode=1, stderr=self.diagnostic)
            with self.lock:
                self.fill_rows += 1
                if self.fill_rows >= self.module.MAX_INSERTS:
                    self.denied.set()
            return self.result(query)
        with self.lock:
            if query.startswith("INSERT INTO `q77612345678n_quota`.quota_neighbor VALUES (NULL)"):
                self.neighbor_rows += 1
                if self.neighbor_rows >= 3:
                    self.ready.set()
            elif query.startswith("START TRANSACTION;"):
                assert self.denied.is_set(), "The independent write must follow the database passing the file cap"
                self.transactions.append(query)
                if self.commit_error:
                    raise AssertionError("Post-denial neighbor transaction refused")
                marker = re.search(r"VALUES\s*\(\s*(-[0-9]+)\s*\)", query)
                assert marker is not None, "Use an independent unique negative marker, never auto-increment"
                if "COMMIT;" in query and self.commit_persists:
                    self.markers.add(int(marker[1]))
                    self.neighbor_rows += 1
            elif query.startswith("SELECT COUNT(*) FROM `q77612345678n_quota`.quota_neighbor"):
                self.count_reads.append(self.neighbor_rows)
                return self.result(query, stdout=str(self.neighbor_rows) + "\n")
            elif query.startswith("SELECT id FROM `q77612345678n_quota`.quota_neighbor WHERE id="):
                marker = int(query.rsplit("=", 1)[1])
                observed = str(marker) if marker in self.markers else ""
                self.marker_reads.append(observed)
                return self.result(query, stdout=observed + "\n")
            elif query.startswith("TRUNCATE TABLE"):
                self.neighbor_rows = 0
                self.markers.clear()
            elif query.startswith("SELECT COUNT(*) FROM `q77612345678_quota`.quota_fill"):
                return self.result(query, stdout=f"{self.fill_rows}\n")
            elif query.startswith("SELECT @@tmpdir"):
                return self.result(query, stdout=self.tmpdir + "\n")
            elif "Created_tmp_disk_tables" in query:
                return self.result(query, stdout=f"16\nCreated_tmp_disk_tables\t{self.disk_temporary_tables}\n")
            else:
                assert query.startswith(("CREATE TABLE", "FLUSH TABLES", "DROP TABLE", "ALTER TABLE")), query
        return self.result(query)

    def exercise(self):
        with (
            TemporaryDirectory() as directory,
            patch.object(self.module, "BACKUP_ROOT", Path(directory) / "backup"),
            patch.object(self.module, "SMALL_DESTINATION", Path(directory) / "small"),
            patch.dict(sys.modules, {"praho_quota_native": self.native}),
            patch.object(self.module, "domain_row", side_effect=self.domain),
            patch.object(self.module, "probe", side_effect=self.probe),
            patch.object(self.module, "sql", side_effect=self.sql),
            patch.object(self.module, "unprivileged", self.file_writes),
            patch.object(self.module, "_remove_fill") as self.removed_fill,
            patch.object(self.module, "run", side_effect=self.native_command),
            patch.object(self.module, "_backup_staging_left", side_effect=self.leftover),
        ):
            self.module.database("victim", "neighbor")


class NativeQuotaDatabaseProofTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        source = Path(settings.BASE_DIR).parents[1] / "tests/virtualmin_lab/native/quota_acceptance.py"
        spec = importlib.util.spec_from_file_location("owned_native_quota_acceptance", source)
        cls.acceptance = importlib.util.module_from_spec(spec)
        # Import must not retain the native-only /usr/local/lib/praho search path.
        with patch.object(sys, "path", list(sys.path)):
            spec.loader.exec_module(cls.acceptance)

    def assert_not_edquot(self, diagnostic):
        boundary = DatabaseBoundary(self.acceptance, diagnostic=diagnostic)
        with self.assertRaisesRegex(AssertionError, "past the file cap failed"):
            boundary.exercise()

    def test_only_fixture_domains_and_virtualmin_s_own_hostname_domain_are_expected(self):
        fqdn = "node-001.native-acc.example.test"
        fixtures = ("q776aaaa.example.invalid", "q776aaaan.example.invalid")
        hostname_domain = {
            "dom": fqdn,
            "user": "_hostname",
            "home": "/home/._hostname",
            "defaulthostdomain": "1",
        }
        unexpected = self.acceptance.unexpected_domains
        self.assertEqual(unexpected([hostname_domain, {"dom": fixtures[0]}], fixtures, fqdn), [])
        for impostor in (
            {**hostname_domain, "defaulthostdomain": "0"},
            {**hostname_domain, "user": "tenant"},
            {**hostname_domain, "home": "/home/tenant"},
            {**hostname_domain, "dom": "other.example.test"},
            {"dom": "tenant.example.test"},
        ):
            with self.subTest(impostor=impostor):
                self.assertEqual(unexpected([impostor], fixtures, fqdn), [impostor["dom"]])

    def test_sql_error_1227_is_not_os_edquot(self):
        self.assert_not_edquot("ERROR 1227 (42000): Access denied; you need a privilege")

    def test_sql_error_1220_is_not_os_edquot(self):
        self.assert_not_edquot("ERROR 1220 (HY000): Error when executing command")

    def test_bare_sql_error_122_is_not_os_edquot(self):
        self.assert_not_edquot("ERROR 122 (HY000): An unrelated SQL failure")

    def test_errno_1220_is_not_os_edquot(self):
        self.assert_not_edquot("InnoDB: errno=1220 while writing a file")

    def test_unrelated_os_error_remains_refused(self):
        self.assert_not_edquot("InnoDB: Operating system error number 121 in a file operation")

    def test_a_real_os_quota_diagnostic_means_the_database_is_still_charged(self):
        for diagnostic in (
            "InnoDB: Operating system error number 122 in a file operation",
            'ERROR 1030 (HY000): Got error 122 "Disk quota exceeded" from storage engine InnoDB',
            "OSError: [Errno 122] Disk quota exceeded",
            "InnoDB: errno=122 while writing a file",
        ):
            with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(AssertionError, "still charged"):
                DatabaseBoundary(self.acceptance, diagnostic=diagnostic).exercise()

    def test_a_database_past_a_full_file_cap_commits_and_the_server_survives(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.exercise()
        self.assertEqual(boundary.fill_rows, self.acceptance.MAX_INSERTS)
        self.assertTrue(any("REPEAT('x',1048576)" in query for query in boundary.statements))  # past the 16 KiB trigger
        self.assertEqual(len(boundary.transactions), 1)
        self.assertIn("COMMIT;", boundary.transactions[0])
        self.assertEqual(boundary.count_reads[-1], boundary.count_reads[0] + 1)
        self.assertEqual(len(boundary.marker_reads), 1)
        self.assertLess(int(boundary.marker_reads[0]), 0)
        self.assertEqual(boundary.probe_calls, 6)
        boundary.native._set_kernel_quota.assert_not_called()  # no lab headroom: nothing needs it now

    def test_tenant_files_still_stop_at_the_cap_before_and_after_the_database_grows(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.exercise()
        self.assertEqual(boundary.file_writes.call_count, 2)
        for call in boundary.file_writes.call_args_list:
            self.assertEqual(call.args[0], "victim")
            self.assertEqual(call.kwargs, {"php": False, "keep": True})
        boundary.removed_fill.assert_called_once_with("victim")

    def test_a_failed_tenant_file_denial_refuses_the_proof(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.file_writes.side_effect = AssertionError("unprivileged writer did not encounter EDQUOT")
        with self.assertRaisesRegex(AssertionError, "did not encounter EDQUOT"):
            boundary.exercise()

    def test_a_database_that_never_passed_the_cap_proves_nothing(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.database_bytes = self.acceptance.LIMIT_KIB * 1024
        with self.assertRaisesRegex(AssertionError, "did not grow past"):
            boundary.exercise()

    def test_database_bytes_showing_up_in_the_group_usage_is_refused(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.used_after_inserts = boundary.used_bytes + 8 * 1024 * 1024
        with self.assertRaisesRegex(AssertionError, "charged to the account"):
            boundary.exercise()

    def test_temporary_work_must_really_reach_disk_at_the_full_cap(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.exercise()
        self.assertTrue(any(query.startswith("ALTER TABLE") and "FORCE" in query for query in boundary.statements))
        boundary = DatabaseBoundary(self.acceptance)
        boundary.disk_temporary_tables = 0
        with self.assertRaisesRegex(AssertionError, "disk-backed"):
            boundary.exercise()

    def test_temporary_files_under_a_tenant_home_are_refused(self):
        for setting in ("/home/shared\t", "/tmp\t/home/shared", "/tmp:/home/shared\t"):  # noqa: S108 -- Fixture settings; nothing is created.
            boundary = DatabaseBoundary(self.acceptance)
            boundary.tmpdir = setting
            with self.subTest(setting=setting), self.assertRaisesRegex(AssertionError, "tenant home"):
                boundary.exercise()

    def test_a_quota_on_mariadbs_own_identity_is_refused(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.mariadb_hard_kib = 1048576
        with self.assertRaisesRegex(AssertionError, "MariaDB's own"):
            boundary.exercise()

    def backup_commands(self, boundary, verb):
        return [argv for argv in boundary.commands if argv[0].endswith("virtualmin") and argv[1] == verb]

    def test_a_database_past_the_file_cap_is_backed_up_and_restored_with_the_caps_back(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.exercise()
        full, small = self.backup_commands(boundary, "backup-domain")
        self.assertIn("--all-features", full)
        self.assertIn("small", small[small.index("--dest") + 1])
        (restore,) = self.backup_commands(boundary, "restore-domain")
        self.assertIn("--only-features", restore)

    def test_the_restore_uses_praho_s_own_feature_list(self):
        from apps.provisioning.virtualmin_validators import WEB_ONLY_VIRTUALMIN_FEATURES  # noqa: PLC0415

        self.assertEqual(self.acceptance.RESTORE_FEATURES, WEB_ONLY_VIRTUALMIN_FEATURES)

    def test_a_dump_no_larger_than_the_cap_proves_nothing(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.dump_bytes = self.acceptance.LIMIT_KIB * 1024
        with self.assertRaisesRegex(AssertionError, "did not exceed the file cap"):
            boundary.exercise()

    def test_caps_left_lifted_after_any_backup_or_restore_are_refused(self):
        for phase in ("full", "small", "restore"):
            boundary = DatabaseBoundary(self.acceptance)
            boundary.caps_lifted_after = {phase}
            with self.subTest(phase=phase), self.assertRaisesRegex(AssertionError, "equal hard UID/GID caps"):
                boundary.exercise()

    def test_a_tenant_owned_dump_left_in_the_home_is_refused(self):
        for phase in ("full", "small", "restore"):
            boundary = DatabaseBoundary(self.acceptance)
            boundary.leftover_after = {phase}
            with self.subTest(phase=phase), self.assertRaisesRegex(AssertionError, "left the tenant-owned dump"):
                boundary.exercise()

    def test_a_backup_that_cannot_fit_its_destination_must_fail_and_unmount(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.backup_exits["small"] = 0
        with self.assertRaisesRegex(AssertionError, "reported success"):
            boundary.exercise()
        self.assertTrue(any(argv[0].endswith("umount") for argv in boundary.commands))

    def test_a_restore_that_loses_rows_is_refused(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.rows_after_restore = 3
        with self.assertRaisesRegex(AssertionError, "rows"):
            boundary.exercise()

    def test_post_denial_transaction_refusal_cannot_certify_neighbor_health(self):
        boundary = DatabaseBoundary(self.acceptance, commit_error=True)
        with self.assertRaisesRegex(AssertionError, "Post-denial neighbor transaction refused"):
            boundary.exercise()

    def test_post_denial_commit_must_preserve_database_pid(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.changed_pid_after_commit = True
        with self.assertRaisesRegex(AssertionError, "post-denial neighbor commit restarted MariaDB"):
            boundary.exercise()
        self.assertEqual(len(boundary.transactions), 1)
        self.assertIn(int(boundary.marker_reads[0]), boundary.markers)
        self.assertEqual(boundary.count_reads[-1], boundary.count_reads[0] + 1)

    def test_post_denial_commit_must_preserve_writer_qualification(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.failed_qualification_after_commit = True
        with self.assertRaisesRegex(AssertionError, "Post-denial writer qualification refused"):
            boundary.exercise()
        self.assertEqual(len(boundary.transactions), 1)
        self.assertIn(int(boundary.marker_reads[0]), boundary.markers)
        self.assertEqual(boundary.count_reads[-1], boundary.count_reads[0] + 1)

    def test_acknowledged_but_unpersisted_post_denial_marker_is_refused(self):
        boundary = DatabaseBoundary(self.acceptance, commit_persists=False)
        with self.assertRaisesRegex(AssertionError, "neighbor.*commit"):
            boundary.exercise()

    def test_a_restarted_server_or_an_unfilled_cap_is_refused(self):
        for changed_pid, used_bytes in ((True, self.acceptance.LIMIT_KIB * 1024), (False, 1)):
            with self.subTest(changed_pid=changed_pid, used_bytes=used_bytes):
                boundary = DatabaseBoundary(self.acceptance)
                boundary.changed_pid, boundary.used_bytes = changed_pid, used_bytes
                with self.assertRaises(AssertionError):
                    boundary.exercise()
