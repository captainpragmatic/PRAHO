"""Destination SQL credentials stay private, bounded to selected schemas and held until activation."""

import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class TargetSQLFixture:
    def __init__(self):
        self.accounts = {("customer", "localhost"): {"hash": "*" + "A" * 40, "locked": True, "grants": []}}
        self.statements = []
        self.fail_after_create = False
        self.schemas = []

    def __call__(self, query):  # noqa: C901, PLR0911, PLR0912 -- explicit native SQL state machine test boundary
        import re  # noqa: PLC0415 -- fixture's tiny native SQL boundary

        self.statements.append(query)
        if query == "SELECT VERSION()":
            return [("10.11.13-MariaDB",)]
        if "AS component_dba" in query:
            return [("1",)]
        if query.startswith("SELECT User, Host FROM mysql.user"):
            return sorted(self.accounts)
        if query.startswith("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA"):
            return self.schemas
        identity = re.search(r"'([^']+)'(?: AND Host = |@)'([^']+)'", query)
        if identity is None:
            raise AssertionError(query)
        key = identity[1], identity[2]
        if query.startswith("CREATE USER"):
            if key in self.accounts:
                raise AssertionError("Recreated an existing native principal")
            self.accounts[key] = {"hash": "*" + "B" * 40, "locked": True, "grants": []}
            if self.fail_after_create:
                raise TimeoutError("Response lost after committed CREATE USER")
            return []
        if query.startswith("DROP USER"):
            del self.accounts[key]
            return []
        row = self.accounts[key]
        if "FROM mysql.global_priv" in query:
            return [("mysql_native_password", row["hash"], "true" if row["locked"] else "false", "[]")]
        if query.startswith("SHOW GRANTS"):
            usage = f"GRANT USAGE ON *.* TO `{key[0]}`@`{key[1]}` IDENTIFIED BY PASSWORD '{row['hash']}'"
            return [(grant,) for grant in [usage, *row["grants"]]]
        if query.startswith("REVOKE ALL"):
            row["grants"] = []
        elif query.startswith("ALTER USER"):
            if "IDENTIFIED" in query:
                row["hash"] = re.search(r"'(\*[A-F0-9]{40})'", query)[1]
            if "ACCOUNT LOCK" in query:
                row["locked"] = True
            if "ACCOUNT UNLOCK" in query:
                row["locked"] = False
        elif query.startswith("GRANT "):
            row["grants"].append(query.replace(f"'{key[0]}'@'{key[1]}'", f"`{key[0]}`@`{key[1]}`"))
        else:
            raise AssertionError(query)
        return []


class ComponentTargetDatabaseTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-target-database.py"
        spec = importlib.util.spec_from_file_location("component_target_database", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name).resolve()
        self.sql = TargetSQLFixture()
        self.operation, self.boot = str(uuid4()), str(uuid4())
        self.private = [
            {
                "user": "webapp",
                "host": "localhost",
                "plugin": "mysql_native_password",
                "authentication_string": "*" + "B" * 40,
                "alternatives": "[]",
                "grants": ["GRANT SELECT, INSERT ON `customer_web`.* TO `webapp`@`localhost`"],
            }
        ]
        auth = ["mysql_native_password", "*" + "B" * 40, "[]"]
        self.principal = {
            "user": "webapp",
            "host": "localhost",
            "locked": False,
            "auth_digest": hashlib.sha256(json.dumps(auth, separators=(",", ":")).encode()).hexdigest(),
            "grants_digest": hashlib.sha256(
                json.dumps(self.private[0]["grants"], separators=(",", ":")).encode()
            ).hexdigest(),
        }
        self.manifest = {
            "source": {"owner": "customer"},
            "databases": [
                {
                    "name": "customer_web",
                    "principals": [self.principal],
                    "isolated": True,
                }
            ],
        }

    def manager(self):
        return self.module.TargetDatabase(
            self.manifest,
            self.private,
            ("localhost",),
            "123456789",
            self.operation,
            "a" * 64,
            state_dir=self.directory,
            boot_id=self.boot,
            execute=self.sql,
        )

    def test_restore_narrows_grants_preserves_hash_and_held_retry_cannot_mutate_or_unlock(self):
        target = self.manager()
        target.apply()
        self.assertTrue(all(row["locked"] for row in self.sql.accounts.values()))
        row = self.sql.accounts[("webapp", "localhost")]
        self.assertEqual(row["hash"], "*" + "B" * 40)
        self.assertEqual(row["grants"], [r"GRANT SELECT, INSERT ON `customer\_web`.* TO `webapp`@`localhost`"])
        before = len(self.sql.statements)
        self.manager().apply()
        self.assertFalse(
            any(query.startswith(("ALTER", "CREATE", "REVOKE", "GRANT")) for query in self.sql.statements[before:])
        )
        self.assertNotIn("*" + "B" * 40, target.journal.path.read_text())
        row["locked"] = False
        with self.assertRaisesRegex(ValueError, "changed"):
            self.manager().verify()

    def test_foreign_username_host_refuses_before_any_ddl(self):
        self.sql.accounts[("webapp", "elsewhere.test")] = dict(self.sql.accounts[("customer", "localhost")])
        with self.assertRaisesRegex(ValueError, "namespace"):
            self.manager().apply()
        self.assertFalse(any(query.startswith(("ALTER", "CREATE", "REVOKE", "GRANT")) for query in self.sql.statements))

    def test_lost_create_response_parks_without_adoption_or_replay(self):
        target = self.manager()
        self.sql.fail_after_create = True
        with self.assertRaises(TimeoutError):
            target.apply()
        self.assertIn(("webapp", "localhost"), self.sql.accounts)
        self.sql.statements.clear()
        with self.assertRaisesRegex(ValueError, "interrupted"):
            self.manager().apply()
        self.assertFalse(any(query.startswith(("ALTER", "CREATE", "REVOKE", "GRANT")) for query in self.sql.statements))

    def test_activation_preserves_original_locks_and_rechecks_native_owner_password(self):
        self.principal["locked"] = True
        target = self.manager()
        target.apply()
        self.sql.accounts[("customer", "localhost")]["hash"] = "*" + "C" * 40
        target.activate()
        self.assertTrue(all(row["locked"] for row in self.sql.accounts.values()))
        self.assertEqual(self.sql.accounts[("webapp", "localhost")]["hash"], "*" + "B" * 40)
        target.activate()

    def test_activation_unlocks_only_originally_unlocked_selected_principals(self):
        target = self.manager()
        target.apply()
        target.activate()
        self.assertFalse(self.sql.accounts[("webapp", "localhost")]["locked"])
        self.assertTrue(self.sql.accounts[("customer", "localhost")]["locked"])
        self.manager().verify(active=True)

    def test_suspended_activation_never_unlocks_selected_accounts(self):
        target = self.manager()
        target.apply()
        target.activate(enabled=False)
        self.assertTrue(all(row["locked"] for row in self.sql.accounts.values()))
        target.verify(active=True)
        with self.assertRaisesRegex(ValueError, "policy"):
            target.activate(enabled=True)

    def test_current_policy_changes_only_selected_locks_without_replaying_credentials_or_grants(self):
        target = self.manager()
        target.apply()
        target.activate()
        before = {key: (row["hash"], list(row["grants"])) for key, row in self.sql.accounts.items()}
        self.sql.statements.clear()
        target.reconcile_policy(enabled=False)
        self.assertTrue(all(row["locked"] for row in self.sql.accounts.values()))
        self.manager().reconcile_policy(enabled=True)
        self.assertFalse(self.sql.accounts[("webapp", "localhost")]["locked"])
        self.assertTrue(self.sql.accounts[("customer", "localhost")]["locked"])
        self.assertEqual(before, {key: (row["hash"], row["grants"]) for key, row in self.sql.accounts.items()})
        writes = [query for query in self.sql.statements if query.startswith(("ALTER", "CREATE", "REVOKE", "GRANT"))]
        self.assertTrue(writes)
        self.assertTrue(
            all(
                query.startswith("ALTER USER ") and " ACCOUNT " in query and "IDENTIFIED" not in query
                for query in writes
            )
        )
        self.manager().verify(active=True)

    def test_current_policy_refuses_changed_identity_before_any_lock_mutation(self):
        target = self.manager()
        target.apply()
        target.activate()
        self.sql.accounts[("webapp", "localhost")]["hash"] = "*" + "F" * 40
        self.sql.statements.clear()
        with self.assertRaisesRegex(ValueError, "authentication"):
            target.reconcile_policy(enabled=False)
        self.assertFalse(any(query.startswith("ALTER") for query in self.sql.statements))

    def test_lost_policy_lock_reply_can_reconcile_exact_owned_principals(self):
        target = self.manager()
        target.apply()
        target.activate()

        def lost_reply(query):
            result = self.sql(query)
            if query == "ALTER USER 'webapp'@'localhost' ACCOUNT LOCK":
                raise TimeoutError("Lost reply after exact account lock")
            return result

        target.execute = lost_reply
        with self.assertRaises(TimeoutError):
            target.reconcile_policy(enabled=False)
        self.assertTrue(self.sql.accounts[("webapp", "localhost")]["locked"])
        self.manager().reconcile_policy(enabled=False)
        self.manager().verify(active=True)

    def test_cleanup_removes_only_receipted_principals_after_native_schema_absence(self):
        target = self.manager()
        target.apply()
        # Native delete removes its own SQL owner, but an independently created
        # application login still requires exact cleanup after schema deletion.
        del self.sql.accounts[("customer", "localhost")]
        target.retire()
        self.assertEqual(self.sql.accounts, {})
        target.retire()
        self.sql.accounts[("webapp", "localhost")] = {"hash": "*" + "F" * 40, "locked": True, "grants": []}
        self.sql.statements.clear()
        with self.assertRaisesRegex(ValueError, "namespace"):
            target.retire()
        self.assertFalse(any(query.startswith("DROP USER") for query in self.sql.statements))

    def test_cleanup_refuses_live_schemas_or_changed_application_identity(self):
        target = self.manager()
        target.apply()
        self.sql.schemas = [("customer_web",)]
        with self.assertRaisesRegex(ValueError, "schema"):
            target.retire()
        self.sql.schemas = []
        self.sql.accounts[("webapp", "localhost")]["hash"] = "*" + "F" * 40
        self.sql.statements.clear()
        with self.assertRaisesRegex(ValueError, "identity"):
            target.retire()
        self.assertFalse(any(query.startswith("DROP USER") for query in self.sql.statements))
