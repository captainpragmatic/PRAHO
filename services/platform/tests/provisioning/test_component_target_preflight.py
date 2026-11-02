"""An existing target Unix/group/schema or any SQL host account must survive component admission."""

import importlib.util
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from tests.provisioning.test_component_migration_manifest import component_manifest


class ComponentTargetPreflightTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-target-preflight.py"
        spec = importlib.util.spec_from_file_location("component_target_preflight", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.manifest = component_manifest()
        self.accounts, self.schemas, self.queries = [], [], []
        self.complete_dba = True

    @staticmethod
    def absent(_name):
        raise KeyError("No existing target identity")

    def sql(self, query):
        self.queries.append(query)
        if query == "SELECT VERSION()":
            return [("10.11.13-MariaDB",)]
        if "AS component_dba" in query:
            return [("1" if self.complete_dba else "0",)]
        if query.startswith("SELECT User, Host FROM mysql.user"):
            return self.accounts
        if query.startswith("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA"):
            return self.schemas
        raise AssertionError("Unexpected or mutating native SQL: " + query)

    def inspect(self, **options):
        return self.module.preflight_target(
            self.manifest,
            execute=self.sql,
            lookup_user=options.get("user", self.absent),
            lookup_group=options.get("group", self.absent),
        )

    def test_absence_proof_covers_native_owner_and_every_selected_username_and_schema(self):
        result = self.inspect()
        self.assertEqual(
            result, {"owner": "customer", "sql_users": ["customer", "webapp"], "schemas": ["customer", "customer_web"]}
        )
        account_query = next(query for query in self.queries if query.startswith("SELECT User, Host"))
        self.assertIn("'customer'", account_query)
        self.assertIn("'webapp'", account_query)
        self.assertNotIn("Host =", account_query)

    def test_unix_user_or_group_collision_refuses_before_any_native_sql(self):
        for kind in ("user", "group"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.inspect(**{kind: lambda _name: object()})
            self.assertEqual(self.queries, [])

    def test_foreign_sql_account_on_any_host_or_existing_schema_cannot_be_adopted(self):
        self.accounts = [("webapp", "retained.example.test")]
        with self.assertRaises(ValueError):
            self.inspect()
        self.accounts, self.schemas = [], [("customer",)]
        with self.assertRaises(ValueError):
            self.inspect()
        self.schemas, self.complete_dba = [], False
        with self.assertRaises(ValueError):
            self.inspect()
