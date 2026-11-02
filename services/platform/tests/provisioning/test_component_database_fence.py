"""Native database fencing locks only isolated website principals and closes their old sessions."""

import importlib.util
import json
import tempfile
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

from tests.provisioning.test_component_mysql_scope import NativeSQLFixture


class FenceSQLFixture(NativeSQLFixture):
    def __init__(self):
        super().__init__()
        self.locked = False
        self.sessions = {42: "webapp"}
        self.lose_lock_receipt = False
        self.reused_id = False

    def __call__(self, query):  # noqa: PLR0911 -- distinct native SQL endpoint fixtures
        if "FROM mysql.global_priv" in query:
            self.statements.append(query)
            return [(self.plugin, self.secret, str(self.locked).lower(), "[]")]
        if query.startswith("ALTER USER"):
            self.statements.append(query)
            self.locked = query.endswith(" ACCOUNT LOCK")
            if self.lose_lock_receipt:
                raise ValueError("SQL connection lost after native lock")
            return []
        if query.startswith("SELECT ID, USER FROM information_schema.PROCESSLIST"):
            self.statements.append(query)
            return [(str(identifier), user) for identifier, user in sorted(self.sessions.items()) if user == "webapp"]
        if query.startswith("SELECT USER FROM information_schema.PROCESSLIST WHERE ID = "):
            self.statements.append(query)
            identifier = int(query.rsplit(" ", 1)[1])
            if self.reused_id:
                return [("retained_mail",)]
            return [(self.sessions[identifier],)] if identifier in self.sessions else []
        if query.startswith("KILL CONNECTION "):
            self.statements.append(query)
            self.sessions.pop(int(query.rsplit(" ", 1)[1]), None)
            return []
        return super().__call__(query)


class ComponentDatabaseFenceTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-database-fence.py"
        spec = importlib.util.spec_from_file_location("component_database_fence", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state_dir = Path(directory.name).resolve() / "state"
        self.sql = FenceSQLFixture()
        self.operation_id = str(uuid4())
        self.boot_id = str(uuid4())

    def fence(self, *, operation_id=None, boot_id=None):
        return self.module.DatabaseFence(
            "123456789",
            operation_id or self.operation_id,
            self.module.mysql.inspect_databases(("customer_web",), ("customer_web",), execute=self.sql)["databases"],
            ("customer_web",),
            state_dir=self.state_dir,
            boot_id=boot_id or self.boot_id,
            execute=self.sql,
        )

    def test_apply_closes_existing_selected_sessions_and_verify_is_readonly(self):
        self.sql.sessions[99] = "retained_mail"
        fence = self.fence()
        fence.apply()
        self.assertTrue(self.sql.locked)
        self.assertEqual(self.sql.sessions, {99: "retained_mail"})
        self.assertEqual(json.loads(fence.journal.path.read_text())["phase"], "held")
        self.assertNotIn("private-native-hash", fence.journal.path.read_text())
        self.sql.statements.clear()
        fence.verify()
        self.assertTrue(all(query.startswith(("SELECT", "SHOW GRANTS")) for query in self.sql.statements))
        fence.release()
        self.assertFalse(self.sql.locked)
        self.assertEqual(self.sql.sessions, {99: "retained_mail"})
        self.assertEqual(json.loads(fence.journal.path.read_text())["phase"], "released")

    def test_originally_locked_principal_is_never_unlocked_by_compensation(self):
        self.sql.locked = True
        fence = self.fence()
        fence.apply()
        fence.release()
        self.assertTrue(self.sql.locked)
        self.assertFalse(any(query.startswith("ALTER USER") for query in self.sql.statements))

    def test_lost_native_lock_receipt_is_parked_and_never_claimed_or_unlocked(self):
        fence = self.fence()
        self.sql.lose_lock_receipt = True
        with self.assertRaises(ValueError):
            fence.apply()
        self.assertTrue(self.sql.locked)
        self.sql.lose_lock_receipt = False
        with self.assertRaisesRegex(ValueError, "receipt"):
            fence.apply()
        with self.assertRaisesRegex(ValueError, "receipt"):
            fence.release()
        self.assertTrue(self.sql.locked)
        self.assertEqual(len([query for query in self.sql.statements if query.startswith("ALTER USER")]), 1)

    def test_changed_grants_and_shared_host_accounts_refuse_without_lock_or_kill(self):
        fence = self.fence()
        self.sql.other_host = True
        with self.assertRaises(ValueError):
            fence.apply()
        self.assertFalse(any(query.startswith(("ALTER USER", "KILL")) for query in self.sql.statements))

    def test_reused_connection_id_is_never_killed(self):
        fence = self.fence()
        self.sql.reused_id = True
        with self.assertRaises(ValueError):
            fence.apply()
        self.assertFalse(any(query.startswith("KILL") for query in self.sql.statements))

    def test_foreign_attempt_or_source_reboot_cannot_release_held_principals(self):
        fence = self.fence()
        fence.apply()
        for changed in ({"operation_id": str(uuid4())}, {"boot_id": str(uuid4())}):
            other = self.fence(**changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                other.release()
        self.assertTrue(self.sql.locked)

    def test_repeated_apply_and_release_do_not_repeat_native_writes(self):
        fence = self.fence()
        fence.apply()
        fence.apply()
        fence.release()
        fence.release()
        self.assertEqual(
            [query for query in self.sql.statements if query.startswith("ALTER USER")],
            ["ALTER USER 'webapp'@'localhost' ACCOUNT LOCK", "ALTER USER 'webapp'@'localhost' ACCOUNT UNLOCK"],
        )

    def test_incomplete_receipt_cannot_silently_leave_a_selected_principal_locked(self):
        fence = self.fence()
        fence.apply()
        state = json.loads(fence.journal.path.read_text())
        state["principals"] = []
        fence.journal.write(state)
        with self.assertRaisesRegex(ValueError, "receipt"):
            fence.release()
        self.assertTrue(self.sql.locked)

    def test_changed_native_authentication_never_gets_unlocked_by_old_compensation(self):
        fence = self.fence()
        fence.apply()
        self.sql.plugin = "unix_socket"
        with self.assertRaises(ValueError):
            fence.release()
        self.assertTrue(self.sql.locked)
        self.assertFalse(any(query.endswith(" ACCOUNT UNLOCK") for query in self.sql.statements))
