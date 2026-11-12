"""An installed node's tenant-charged databases are repaired quiesced, then rescanned, and resume after interruption."""

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

FILES = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"
MARIADB, TENANT = (110, 113), (1001, 1002)


def _load(name):
    spec = importlib.util.spec_from_file_location(f"repair_{name}", FILES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Ownership:
    """Doubles ownership and modes over a real temporary tree, so chown works unprivileged."""

    def __init__(self, native):
        self.native = native
        self.owners, self.modes = {}, {}
        self.chown_failures_left = None

    def set(self, path, owner, mode=None):
        self.owners[Path(path).name] = owner
        if mode is not None:
            self.modes[Path(path).name] = mode

    def lstat(self, path):
        fields = list(self.real_lstat(path))
        name = Path(path).name
        if name in self.owners:
            fields[stat.ST_UID], fields[stat.ST_GID] = self.owners[name]
        if name in self.modes:
            fields[stat.ST_MODE] = stat.S_IFMT(fields[stat.ST_MODE]) | self.modes[name]
        return os.stat_result(fields)

    def chown(self, path, uid, gid, *, follow_symlinks=True):
        assert follow_symlinks is False, "repair must never follow a link"
        if self.chown_failures_left == 0:
            raise OSError("interrupted")
        if self.chown_failures_left is not None:
            self.chown_failures_left -= 1
        self.owners[Path(path).name] = (uid, gid)

    def chmod(self, path, mode):
        self.modes[Path(path).name] = mode

    def __enter__(self):
        self.real_lstat = os.lstat
        self.patches = [
            patch.object(Path, "lstat", lambda path: self.lstat(path)),  # noqa: PLW0108 -- Binds as a Path method.
            patch.object(self.native.os, "chown", self.chown),
            patch.object(self.native.os, "chmod", self.chmod),
        ]
        for item in self.patches:
            item.start()
        return self

    def __exit__(self, *_exc):
        for item in self.patches:
            item.stop()


class RepairDirectoryTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.native = _load("praho_quota_native")

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.schema = Path(directory.name).resolve() / "shop_db"
        self.schema.mkdir()
        (self.schema / "posts.ibd").write_bytes(b"x")
        (self.schema / "users.ibd").write_bytes(b"x")
        self.fs = Ownership(self.native)
        self.fs.set(self.schema, (MARIADB[0], TENANT[1]), 0o2750)
        self.fs.set("posts.ibd", (MARIADB[0], TENANT[1]))
        self.fs.set("users.ibd", MARIADB)

    def repair(self):
        self.native.repair_database_directory(
            self.schema, writer=MARIADB, tenant=TENANT, device=self.schema.stat().st_dev
        )

    def test_repair_results_in_exactly_what_the_probe_requires(self):
        with self.fs:
            self.repair()
            self.native.qualify_database_directory(
                self.schema, writer=MARIADB, tenant=TENANT, device=self.schema.stat().st_dev
            )
        self.assertFalse(self.fs.modes["shop_db"] & stat.S_ISGID)

    def test_a_foreign_owner_is_refused_and_nothing_is_changed(self):
        self.fs.set("users.ibd", (999, MARIADB[1]))
        with self.fs, self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "users.ibd"):
            self.repair()
        self.assertEqual(self.fs.owners["posts.ibd"], (MARIADB[0], TENANT[1]))

    def test_a_world_writable_entry_is_refused_before_any_change(self):
        self.fs.modes["users.ibd"] = 0o666
        with self.fs, self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "users.ibd"):
            self.repair()
        self.assertEqual(self.fs.owners["posts.ibd"], (MARIADB[0], TENANT[1]))

    def test_the_preflight_refuses_what_the_repair_would_and_changes_nothing(self):
        self.fs.set("users.ibd", (999, MARIADB[1]))
        with self.fs, self.assertRaisesRegex(self.native.DatabaseStorageRefusalError, "users.ibd"):
            self.native.preflight_database_directory(
                self.schema, writer=MARIADB, tenant=TENANT, device=self.schema.stat().st_dev
            )
        self.assertEqual(self.fs.owners["posts.ibd"], (MARIADB[0], TENANT[1]))
        self.assertEqual(self.fs.modes["shop_db"], 0o2750)

    def test_a_link_inside_a_database_is_refused(self):
        (self.schema / "evil.ibd").symlink_to("/etc/passwd")
        with self.fs, self.assertRaises(self.native.DatabaseStorageRefusalError):
            self.repair()


class RepairOrchestrationTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.node = _load("praho_hosting_node")

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name).resolve()
        self.identity = {"domain_id": "12345", "domain": "shop.test", "uid": TENANT[0], "gid": TENANT[1]}
        self.request = {"identity": "a" * 64, "token": str(uuid4()), "database_repair": self.identity}
        self.domain = {"id": "12345", "dom": "shop.test", "db_mysql": "shop_db"}
        self.account = SimpleNamespace(pw_uid=TENANT[0], pw_gid=TENANT[1], pw_dir="/home/shop")
        self.statements = []
        self.principals = [["shop", "localhost", "false"], ["shop_ro", "%", "true"]]
        self.processlist = ["41"]
        self.backend = Mock()
        self.backend._domain.return_value = (self.domain, self.account)
        self.sibling = ModuleType("praho_quota_native")
        self.sibling.NativeQuotaBackend = Mock(return_value=self.backend)
        self.sibling._database_writer_qualified = Mock(return_value=MARIADB)
        self.sibling.repair_database_directory = Mock()
        self.sibling.repairable_database_layout = Mock()
        self.sibling.preflight_database_directory = Mock()
        self.global_writers = []
        self.definer_objects = []

    def sql(self, query):
        self.statements.append(query)
        if "FROM mysql.db" in query:
            return "\n".join(json.dumps(row) for row in self.principals)
        if "FROM mysql.user" in query:
            return "\n".join(json.dumps(row) for row in self.global_writers)
        if "information_schema.ROUTINES" in query:
            return "\n".join(json.dumps(row) for row in self.definer_objects)
        if "@@datadir" in query:
            return f"{self.state}/\t1"
        if "PROCESSLIST" in query:
            rows, self.processlist = self.processlist, []
            return "\n".join(rows)
        return ""

    def statements_with(self, needle):
        return [query for query in self.statements if needle in query]

    def repair(self):
        with (
            patch.object(self.node, "STATE", self.state),
            patch.object(self.node, "_sql", self.sql),
            patch.object(self.node, "_read", lambda path, **_k: path.read_text()),
            patch.object(self.node, "_write", lambda path, text: path.write_text(text)),
            patch.dict(sys.modules, {"praho_quota_native": self.sibling}),
        ):
            self.node._repair_database_storage(self.request)

    def journal(self):
        return self.state / "database-repair-12345.json"

    def test_writes_stop_before_ownership_changes_and_return_after_the_rescan(self):
        order = []
        self.sibling.repair_database_directory.side_effect = lambda *_a, **_k: order.append(
            ("repair", len(self.statements_with("ACCOUNT LOCK")), len(self.statements_with("KILL CONNECTION 41")))
        )
        self.backend._storage.side_effect = lambda *_a: order.append(("rescan", len(self.statements_with("UNLOCK"))))
        self.repair()
        self.assertEqual(order, [("repair", 1, 1), ("rescan", 0)])
        self.assertEqual(len(self.statements_with("ACCOUNT UNLOCK")), 1)
        self.assertFalse(self.journal().exists())

    def test_an_account_already_locked_by_someone_else_stays_locked(self):
        self.repair()
        self.assertEqual([query for query in self.statements_with("ALTER USER") if "shop_ro" in query], [])
        self.assertEqual(self.statements_with("ACCOUNT UNLOCK"), ["ALTER USER 'shop'@'localhost' ACCOUNT UNLOCK"])

    def test_grants_are_looked_up_without_depending_on_the_sql_mode(self):
        self.repair()
        (query,) = self.statements_with("FROM mysql.db")
        self.assertIn("0x" + b"shop_db".hex(), query)
        self.assertNotIn("\\", query)

    def test_the_mismatched_identity_is_refused_before_any_write(self):
        self.identity["uid"] = 4242
        with self.assertRaisesRegex(ValueError, "identity"):
            self.repair()
        self.assertEqual(self.statements_with("ALTER USER"), [])

    def test_a_system_account_with_a_database_grant_is_refused(self):
        self.principals.append(["root", "localhost", "false"])
        with self.assertRaisesRegex(ValueError, "system account"):
            self.repair()
        self.assertEqual(self.statements_with("ALTER USER"), [])

    def test_an_unexpected_principal_spelling_is_refused(self):
        self.principals.append(["x'; DROP", "localhost", "false"])
        with self.assertRaises(ValueError):
            self.repair()
        self.assertEqual(self.statements_with("ALTER USER"), [])

    def test_a_disconnect_that_never_finishes_keeps_writes_stopped(self):
        self.processlist = ["41"]

        def stuck(query):
            self.statements.append(query)
            if "FROM mysql.db" in query:
                return json.dumps(["shop", "localhost", "false"])
            if "@@datadir" in query:
                return f"{self.state}/\t1"
            return "41" if "PROCESSLIST" in query else ""

        self.sql = stuck
        with patch.object(self.node, "sleep"), self.assertRaisesRegex(ValueError, "still connected"):
            self.repair()
        self.sibling.repair_database_directory.assert_not_called()
        self.assertTrue(self.journal().exists())
        self.assertEqual(self.statements_with("UNLOCK"), [])

    def test_an_interrupted_repair_keeps_writes_stopped_then_resumes_without_adopting_foreign_locks(self):
        self.sibling.repair_database_directory.side_effect = [OSError("interrupted"), None]
        with self.assertRaises(OSError):
            self.repair()
        self.assertTrue(self.journal().exists())
        self.assertEqual(self.statements_with("UNLOCK"), [])
        # The rerun sees its own lock as already locked; the journal, not the current flag, says whose it is.
        self.principals = [["shop", "localhost", "true"], ["shop_ro", "%", "true"]]
        self.statements.clear()
        self.processlist = []
        self.repair()
        self.assertEqual(self.statements_with("ACCOUNT UNLOCK"), ["ALTER USER 'shop'@'localhost' ACCOUNT UNLOCK"])
        self.assertFalse(self.journal().exists())

    def test_a_failing_rescan_keeps_writes_stopped_and_can_be_rerun(self):
        refused = ValueError("Database shop_db: posts.ibd is not a MariaDB-owned file")
        self.backend._storage.side_effect = [refused, None]
        with self.assertRaisesRegex(ValueError, "posts.ibd"):
            self.repair()
        self.assertEqual(self.statements_with("UNLOCK"), [])
        self.principals = [["shop", "localhost", "true"]]
        self.processlist = []
        self.repair()
        self.assertEqual(len(self.statements_with("ACCOUNT UNLOCK")), 1)

    def test_an_unrepairable_layout_is_refused_before_any_write_stops(self):
        self.sibling.repairable_database_layout.side_effect = ValueError("Database shop_db: isolated per-table")
        with self.assertRaisesRegex(ValueError, "isolated per-table"):
            self.repair()
        self.assertEqual(self.statements_with("ALTER USER"), [])
        self.assertFalse(self.journal().exists())

    def test_file_per_table_off_is_refused_before_any_write_stops(self):
        real = self.sql

        def off(query):
            return f"{self.state}/\t0" if "@@datadir" in query else real(query)

        self.sql = off
        with self.assertRaisesRegex(ValueError, "Per-table"):
            self.repair()
        self.assertEqual(self.statements_with("ALTER USER"), [])

    def test_a_rerun_cannot_silently_drop_a_database_from_the_repair(self):
        self.sibling.repair_database_directory.side_effect = [OSError("interrupted")]
        with self.assertRaises(OSError):
            self.repair()
        self.domain["db_mysql"] = ""
        self.principals = []
        self.statements.clear()
        with self.assertRaisesRegex(ValueError, "database list"):
            self.repair()
        self.assertEqual(self.statements_with("UNLOCK"), [])

    def test_a_session_that_vanishes_before_its_kill_is_not_a_failure(self):
        real = self.sql

        def vanishing(query):
            if query.startswith("KILL CONNECTION"):
                self.statements.append(query)
                raise ValueError("Unknown thread id")
            return real(query)

        self.sql = vanishing
        with patch.object(self.node, "sleep"):
            self.repair()
        self.assertFalse(self.journal().exists())

    def assert_refused_before_anything_stops(self, *names):
        with self.assertRaises(ValueError) as refused:
            self.repair()
        for name in names:
            self.assertIn(name, str(refused.exception))
        self.assertEqual(self.statements_with("ALTER USER"), [])
        self.assertEqual(self.statements_with("KILL"), [])
        self.assertFalse(self.journal().exists())
        self.sibling.repair_database_directory.assert_not_called()

    def test_a_login_with_global_write_privileges_is_refused_by_name(self):
        self.global_writers = [["reporting", "%"]]
        self.assert_refused_before_anything_stops("global privileges", "'reporting'@'%'")

    def test_a_definer_routine_elsewhere_that_runs_as_the_account_is_refused_by_name(self):
        self.definer_objects = [["routine", "analytics", "sync_orders", "shop@localhost"]]
        self.assert_refused_before_anything_stops("routine analytics.sync_orders", "shop@localhost")

    def test_definer_objects_of_other_accounts_or_inside_the_account_are_supported(self):
        self.definer_objects = [
            ["routine", "analytics", "report", "other@localhost"],
            ["routine", "shop_db", "cleanup", "shop@localhost"],
            ["trigger", "shop_db", "audit", "shop@localhost"],
            ["view", "sys", "version", "mariadb.sys@localhost"],
        ]
        self.repair()
        self.assertFalse(self.journal().exists())

    def test_an_event_that_writes_as_the_account_or_in_its_database_is_refused(self):
        for event in (["event", "analytics", "nightly", "shop@localhost"], ["event", "shop_db", "purge", "x@localhost"]):
            self.definer_objects = [event]
            with self.subTest(event=event):
                self.assert_refused_before_anything_stops(f"event {event[1]}.{event[2]}")

    def test_a_role_granted_on_the_account_s_database_is_refused_by_name(self):
        self.principals.append(["shop_writers", "", "false"])
        self.assert_refused_before_anything_stops("role 'shop_writers'")

    def test_routine_execute_grants_on_the_account_s_databases_are_looked_up_too(self):
        self.repair()
        (query,) = self.statements_with("FROM mysql.db")
        self.assertIn("mysql.procs_priv", query)

    def test_every_database_directory_is_preflighted_before_writes_stop(self):
        self.domain["db_mysql"] = "shop_db shop_logs"
        self.sibling.preflight_database_directory.side_effect = [
            None,
            ValueError("Database shop_logs: users.ibd has an unexpected owner or type"),
        ]
        self.assert_refused_before_anything_stops("shop_logs", "users.ibd")
        self.assertEqual(self.sibling.preflight_database_directory.call_count, 2)

    def test_the_directories_are_validated_again_after_writes_stop(self):
        order = []
        self.sibling.preflight_database_directory.side_effect = lambda *_a, **_k: order.append(
            ("preflight", len(self.statements_with("ACCOUNT LOCK")))
        )
        self.sibling.repair_database_directory.side_effect = lambda *_a, **_k: order.append(
            ("repair", len(self.statements_with("ACCOUNT LOCK")))
        )
        self.repair()
        self.assertEqual(order, [("preflight", 0), ("repair", 1)])

    def test_a_journal_for_another_owner_is_refused(self):
        self.journal().write_text(json.dumps({"domain_id": "12345", "uid": 9, "gid": 9, "locked": []}))
        with self.assertRaisesRegex(ValueError, "journal"):
            self.repair()
        self.assertEqual(self.statements_with("ALTER USER"), [])

    def test_perform_reaches_repair_only_with_a_token_under_the_operation_lock(self):
        for request in ({"identity": "a" * 64}, {"identity": "a" * 64, "token": "nope"}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.node.perform("repair_database_storage", request)

    def test_perform_runs_the_repair_and_fences_its_token(self):
        with (
            patch.object(self.node, "STATE", self.state),
            patch.object(self.node, "_repair_database_storage") as repair,
            patch.object(self.node, "inspect", return_value={"quota": {}}),
            patch.object(self.node, "_write", lambda path, text: path.write_text(text)),
        ):
            result = self.node.perform("repair_database_storage", self.request)
        repair.assert_called_once_with(self.request)
        self.assertEqual(result["fenced_token"], self.request["token"])
        self.assertTrue((self.state / ("cancelled-" + self.request["token"])).exists())
