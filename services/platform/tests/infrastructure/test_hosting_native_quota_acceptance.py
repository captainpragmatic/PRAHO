"""Acceptance decisions with SQL/OS boundaries doubled, never physical quota proof."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from threading import Event, Lock
from types import ModuleType
from unittest.mock import Mock, patch

from django.conf import settings
from django.test import SimpleTestCase


class DatabaseBoundary:
    """In-memory transactional SQL boundary; the acceptance/thread algorithm stays real."""

    def __init__(self, module, *, diagnostic="Disk quota exceeded", commit_error=False, commit_persists=True):
        self.module = module
        self.diagnostic = diagnostic
        self.commit_error = commit_error
        self.commit_persists = commit_persists
        self.ready, self.denied = Event(), Event()
        self.lock = Lock()
        self.neighbor_rows = 0
        self.markers = set()
        self.transactions = []
        self.count_reads = []
        self.marker_reads = []
        self.probe_calls = 0
        self.pid_reads = 0
        self.changed_pid = False
        self.used_bytes = module.LIMIT_KIB * 1024
        self.native = ModuleType("praho_quota_native")
        self.native._database_writer_qualified = Mock()
        self.native._set_kernel_quota = Mock()
        self.native._run = self.read_native

    def read_native(self, arguments):
        if arguments[0] == "/usr/bin/systemctl":
            self.pid_reads += 1
            return "999" if self.changed_pid and self.pid_reads > 1 else "777"
        assert arguments[0] == "/usr/bin/findmnt"
        return json.dumps({"filesystems": [{"source": "/dev/owned-fixture-only"}]})

    def domain(self, name):
        assert name in {"victim", "neighbor"}
        user = "q77612345678" + ("n" if name == "neighbor" else "")
        return {"user": user, "gid": "1001", "home": "/home/" + user}

    def probe(self, _domain):
        self.probe_calls += 1
        return {"gid_used_bytes": self.used_bytes}

    @staticmethod
    def result(query, *, stdout="", returncode=0, stderr=""):
        return subprocess.CompletedProcess(["mariadb", query], returncode, stdout, stderr)

    def sql(self, query, *, allow_error=False):
        if query.startswith("INSERT INTO `q77612345678_quota`.quota_fill"):
            assert allow_error
            assert self.ready.wait(2), "Concurrent neighbor never committed its required baseline"
            self.denied.set()
            return self.result(query, returncode=1, stderr=self.diagnostic)
        with self.lock:
            if query.startswith("INSERT INTO `q77612345678n_quota`.quota_neighbor VALUES (NULL)"):
                self.neighbor_rows += 1
                if self.neighbor_rows >= 3:
                    self.ready.set()
            elif query.startswith("START TRANSACTION;"):
                assert self.denied.is_set(), "The independent write must follow victim denial"
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
            else:
                assert query.startswith(("CREATE TABLE", "FLUSH TABLES", "DROP TABLE")), query
        return self.result(query)

    def exercise(self):
        with (
            patch.dict(sys.modules, {"praho_quota_native": self.native}),
            patch.object(self.module, "domain_row", side_effect=self.domain),
            patch.object(self.module, "probe", side_effect=self.probe),
            patch.object(self.module, "sql", side_effect=self.sql),
            patch.object(self.module, "run", return_value=self.result("journalctl")),
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
        with self.assertRaisesRegex(AssertionError, "did not prove EDQUOT"):
            boundary.exercise()

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

    def test_real_os_quota_diagnostic_forms_remain_accepted(self):
        for diagnostic in (
            "InnoDB: Operating system error number 122 in a file operation",
            'ERROR 1030 (HY000): Got error 122 "Disk quota exceeded" from storage engine InnoDB',
            "OSError: [Errno 122] Disk quota exceeded",
            "InnoDB: errno=122 while writing a file",
        ):
            with self.subTest(diagnostic=diagnostic):
                DatabaseBoundary(self.acceptance, diagnostic=diagnostic).exercise()

    def test_independent_neighbor_transaction_persists_marker_after_denial(self):
        boundary = DatabaseBoundary(self.acceptance)
        boundary.exercise()
        self.assertEqual(len(boundary.transactions), 1)
        self.assertIn("COMMIT;", boundary.transactions[0])
        self.assertEqual(boundary.count_reads[-1], boundary.count_reads[0] + 1)
        self.assertEqual(len(boundary.marker_reads), 1)
        self.assertLess(int(boundary.marker_reads[0]), 0)
        self.assertEqual(boundary.probe_calls, 3)
        self.assertGreaterEqual(boundary.native._database_writer_qualified.call_count, 1)
        self.assertEqual(boundary.native._set_kernel_quota.call_count, 2)

    def test_post_denial_transaction_refusal_cannot_certify_neighbor_health(self):
        boundary = DatabaseBoundary(self.acceptance, commit_error=True)
        with self.assertRaisesRegex(AssertionError, "Post-denial neighbor transaction refused"):
            boundary.exercise()

    def test_acknowledged_but_unpersisted_post_denial_marker_is_refused(self):
        boundary = DatabaseBoundary(self.acceptance, commit_persists=False)
        with self.assertRaisesRegex(AssertionError, "neighbor.*commit"):
            boundary.exercise()

    def test_existing_pid_and_physical_group_accounting_controls_remain(self):
        for changed_pid, used_bytes in ((True, self.acceptance.LIMIT_KIB * 1024), (False, 1)):
            with self.subTest(changed_pid=changed_pid, used_bytes=used_bytes):
                boundary = DatabaseBoundary(self.acceptance)
                boundary.changed_pid, boundary.used_bytes = changed_pid, used_bytes
                with self.assertRaises(AssertionError):
                    boundary.exercise()
