"""Source database inspection must isolate website grants without touching retained mail authentication."""

import hashlib
import importlib.util
import json
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


class NativeSQLFixture:
    def __init__(self):
        self.statements = []
        self.shared = False
        self.events = False
        self.global_writer = False
        self.roles = False
        self.plugin = "mysql_native_password"
        self.secret = "*private-native-hash-never-in-manifest"
        self.other_host = False
        self.complete_dba = True
        self.unsafe_view_definer = False
        self.unsafe_event_definer = False

    def metadata(self, query):
        if query == "SELECT VERSION()":
            return [("10.11.13-MariaDB",)]
        if "AS component_dba" in query:
            return [("1" if self.complete_dba else "0",)]
        if "DEFAULT_CHARACTER_SET_NAME" in query:
            return [("customer_web", "utf8mb4", "utf8mb4_general_ci", "16384")]
        if "AS component_accounts" in query:
            return [("webapp", "localhost")]
        return None

    def __call__(self, query):  # noqa: PLR0911 -- distinct native SQL endpoint fixtures
        self.statements.append(query)
        metadata = self.metadata(query)
        if metadata is not None:
            return metadata
        if "FROM mysql.global_priv" in query:
            return [(self.plugin, self.secret, "false", "[]")]
        if query.startswith("SELECT Host FROM mysql.user"):
            return [("localhost",), ("retained.example.test",)] if self.other_host else [("localhost",)]
        if query.startswith("SHOW GRANTS"):
            return [
                (f"GRANT USAGE ON *.* TO `webapp`@`localhost` IDENTIFIED BY PASSWORD '{self.secret}'",),
                ("GRANT ALL PRIVILEGES ON `customer_web`.* TO `webapp`@`localhost`",),
            ]
        if "AS outside_scope" in query:
            return [("customer_mail",)] if self.shared else []
        if "FROM mysql.roles_mapping" in query:
            return [("shared_role",)] if self.roles else []
        if "FROM information_schema.EVENTS" in query and "AND STATUS = 'ENABLED'" in query:
            return [("1" if self.events else "0",)]
        if "AS unsafe_definers" in query:
            unsafe = (self.unsafe_view_definer and "information_schema.VIEWS" in query) or (
                self.unsafe_event_definer and "information_schema.EVENTS" in query
            )
            return [("1" if unsafe else "0",)]
        if "AS global_writers" in query:
            return [("1" if self.global_writer else "0",)]
        raise AssertionError("Unexpected native SQL boundary: " + query)


class ComponentMySQLScopeTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-mysql.py"
        spec = importlib.util.spec_from_file_location("component_mysql_scope", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.sql = NativeSQLFixture()

    def inspect(self):
        return self.module.inspect_databases(("customer_web",), ("customer_web", "customer_mail"), execute=self.sql)

    def test_wildcard_grants_expand_only_into_exact_selected_schemas(self):
        grants = [
            "GRANT USAGE ON *.* TO `webapp`@`localhost`",
            r"GRANT SELECT, INSERT ON `customer\_%`.* TO `webapp`@`localhost` WITH GRANT OPTION",
        ]
        self.assertEqual(
            self.module.selected_schema_grants(grants, "webapp", "localhost", ("customer_web", "customer_uploads")),
            [("SELECT, INSERT", "customer_uploads", True), ("SELECT, INSERT", "customer_web", True)],
        )

    def test_unselected_or_unrecognized_grants_are_never_replayed(self):
        for grant in (
            "GRANT ALL PRIVILEGES ON *.* TO `webapp`@`localhost`",
            "GRANT SELECT ON `retained_mail`.* TO `webapp`@`localhost`",
            "GRANT SELECT ON `customer_web`.`table` TO `webapp`@`localhost`",
            "GRANT SELECT ON `customer_web`.* TO `foreign`@`localhost`",
            "GRANT SELECT ON `customer_web`.* TO `webapp`@`localhost`; DROP DATABASE retained_mail",
        ):
            with self.subTest(grant=grant), self.assertRaises(ValueError):
                self.module.selected_schema_grants([grant], "webapp", "localhost", ("customer_web",))

    def test_schema_underscore_is_literal_when_rendered_on_the_target(self):
        self.assertEqual(self.module.exact_schema("customer_web"), r"`customer\_web`")
        for name in ("customer`web", "customer%", "customer/web"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.module.exact_schema(name)

    def test_native_owner_password_must_match_only_selected_application_authentication(self):
        password = "selected application password"
        first = hashlib.sha1(password.encode(), usedforsecurity=False).digest()
        native_hash = "*" + hashlib.sha1(first, usedforsecurity=False).hexdigest().upper()
        auth = ["mysql_native_password", native_hash, "[]"]
        principal = {
            "user": "customer", "host": "localhost",
            "auth_digest": hashlib.sha256(json.dumps(auth, separators=(",", ":")).encode()).hexdigest(),
        }
        selected = [{"principals": [principal]}]
        native = {"user": "customer", "pass": "retained Unix password", "mysql_pass": password}
        self.assertEqual(self.module.native_owner_password(native, selected), password)
        native["mysql_pass"] = "stale credential metadata"
        with self.assertRaisesRegex(ValueError, "native owner SQL"):
            self.module.native_owner_password(native, selected)
        principal["user"] = "independent_app"
        self.assertIsNone(self.module.native_owner_password(native, selected))

    def test_readonly_inspection_returns_exact_isolated_scope_without_credentials(self):
        result = self.inspect()
        self.assertEqual(result["preparation"], [])
        self.assertEqual(len(result["databases"]), 1)
        database = result["databases"][0]
        self.assertEqual((database["name"], database["bytes"], database["isolated"]), ("customer_web", 16384, True))
        principal = database["principals"][0]
        self.assertEqual((principal["user"], principal["host"], principal["locked"]), ("webapp", "localhost", False))
        self.assertEqual(len(principal["auth_digest"]), 64)
        self.assertEqual(len(principal["grants_digest"]), 64)
        self.assertNotIn("private-native-hash", str(result))
        self.assertTrue(all(query.startswith(("SELECT", "SHOW GRANTS")) for query in self.sql.statements))

    def test_shared_principal_is_preparation_and_is_never_locked(self):
        self.sql.shared = True
        result = self.inspect()
        self.assertFalse(result["databases"][0]["isolated"])
        self.assertIn("retained", " ".join(result["preparation"]))
        self.assertFalse(any("ALTER USER" in query for query in self.sql.statements))

    def test_proxy_grant_cannot_hide_access_to_retained_accounts(self):
        original = self.sql

        def proxy(query):
            rows = original(query)
            if query.startswith("SHOW GRANTS"):
                return [*rows, ("GRANT PROXY ON `retained_mail`@`localhost` TO `webapp`@`localhost`",)]
            return rows

        result = self.module.inspect_databases(("customer_web",), ("customer_web", "customer_mail"), execute=proxy)
        self.assertFalse(result["databases"][0]["isolated"])
        self.assertIn("proxy", " ".join(result["preparation"]).lower())

    def test_views_and_disabled_events_with_retained_definers_require_preparation(self):
        for attribute in ("unsafe_view_definer", "unsafe_event_definer"):
            self.sql = NativeSQLFixture()
            setattr(self.sql, attribute, True)
            with self.subTest(attribute=attribute):
                result = self.inspect()
                self.assertFalse(result["databases"][0]["isolated"])
                self.assertIn("definer", " ".join(result["preparation"]))

    def test_global_writers_roles_and_events_require_preparation(self):
        for attribute in ("global_writer", "roles", "events"):
            self.sql = NativeSQLFixture()
            setattr(self.sql, attribute, True)
            with self.subTest(attribute=attribute):
                self.assertTrue(self.inspect()["preparation"])

    def test_unqualified_authentication_plugin_is_not_exported_as_a_durable_target_login(self):
        self.sql.plugin = "unix_socket"
        result = self.inspect()
        self.assertTrue(result["preparation"])
        self.assertIn("plugin", " ".join(result["preparation"]))

    def test_database_not_owned_by_native_domain_refuses_before_sql(self):
        with self.assertRaises(ValueError):
            self.module.inspect_databases(("unrelated_customer",), ("customer_web",), execute=self.sql)
        self.assertEqual(self.sql.statements, [])

    def test_database_name_cannot_inject_native_sql(self):
        with self.assertRaises(ValueError):
            self.module.inspect_databases(("web'; DROP DATABASE mail;--",), ("customer_web",), execute=self.sql)
        self.assertEqual(self.sql.statements, [])

    def test_unreadable_privileges_are_not_treated_as_an_empty_scope(self):
        def denied(query):
            raise ValueError("native permission denied")

        with self.assertRaisesRegex(ValueError, "permission"):
            self.module.inspect_databases(("customer_web",), ("customer_web",), execute=denied)

    def test_same_username_on_a_retained_host_cannot_be_killed_as_a_website_session(self):
        self.sql.other_host = True
        result = self.inspect()
        self.assertFalse(result["databases"][0]["isolated"])
        self.assertIn("host accounts", " ".join(result["preparation"]))

    def test_limited_dba_cannot_claim_complete_privilege_or_session_inventory(self):
        self.sql.complete_dba = False
        with self.assertRaisesRegex(ValueError, "privileges"):
            self.inspect()

    def test_untrusted_principal_identity_cannot_inject_qualification_sql(self):
        original = self.sql

        def malformed(query):
            if "AS component_accounts" in query:
                return [("webapp'; DROP USER root;--", "localhost")]
            return original(query)

        with self.assertRaises(ValueError):
            self.module.inspect_databases(("customer_web",), ("customer_web",), execute=malformed)
        self.assertFalse(any("DROP USER" in query for query in original.statements))
