"""Migration coverage for preserving a distinct customer billing address."""

from __future__ import annotations

import importlib
import sqlite3
from types import TracebackType
from typing import Any

from django.test import SimpleTestCase


class _CursorContext:
    def __init__(self, database: sqlite3.Connection) -> None:
        self.cursor = database.cursor()

    def __enter__(self) -> sqlite3.Cursor:
        return self.cursor

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.cursor.close()


class _MigrationConnection:
    def __init__(self, database: sqlite3.Connection) -> None:
        self.database = database

    def cursor(self) -> _CursorContext:
        return _CursorContext(self.database)


class AddressBooleanFlagMigrationTest(SimpleTestCase):
    def setUp(self) -> None:
        self.database = sqlite3.connect(":memory:")
        self.database.execute(
            """
            CREATE TABLE customer_addresses (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                address_type TEXT NOT NULL,
                is_primary BOOLEAN NOT NULL DEFAULT FALSE,
                is_billing BOOLEAN NOT NULL DEFAULT FALSE,
                is_current BOOLEAN NOT NULL DEFAULT TRUE,
                deleted_at TEXT NULL
            )
            """
        )

    def tearDown(self) -> None:
        self.database.close()

    def _schema_editor(self) -> Any:
        return type(
            "SchemaEditor",
            (),
            {"connection": _MigrationConnection(self.database)},
        )()

    def _run_migration(self) -> None:
        migration = importlib.import_module(
            "apps.customers.migrations.0017_address_boolean_flags"
        )
        schema_editor = self._schema_editor()
        migration.migrate_address_type_to_flags(None, schema_editor)

    def _flags(self, address_id: int) -> tuple[bool, bool]:
        row = self.database.execute(
            "SELECT is_primary, is_billing FROM customer_addresses WHERE id = ?",
            [address_id],
        ).fetchone()
        self.assertIsNotNone(row)
        return bool(row[0]), bool(row[1])

    def test_distinct_billing_address_is_not_overwritten_by_primary(self) -> None:
        self.database.executemany(
            """
            INSERT INTO customer_addresses
                (id, customer_id, address_type, is_current)
            VALUES (?, ?, ?, TRUE)
            """,
            [
                (1, 100, "primary"),
                (2, 100, "billing"),
            ],
        )

        self._run_migration()

        self.assertEqual(self._flags(1), (True, False))
        self.assertEqual(self._flags(2), (False, True))

    def test_single_primary_address_keeps_both_roles(self) -> None:
        self.database.execute(
            """
            INSERT INTO customer_addresses
                (id, customer_id, address_type, is_current)
            VALUES (1, 100, 'primary', TRUE)
            """
        )

        self._run_migration()

        self.assertEqual(self._flags(1), (True, True))

    def test_corrective_migration_repairs_previously_double_flagged_primary(self) -> None:
        self.database.executemany(
            """
            INSERT INTO customer_addresses
                (id, customer_id, address_type, is_primary, is_billing, is_current)
            VALUES (?, ?, '', ?, ?, TRUE)
            """,
            [
                (1, 100, True, True),
                (2, 100, False, True),
            ],
        )
        migration = importlib.import_module(
            "apps.customers.migrations.0021_repair_address_billing_flags"
        )

        migration.repair_address_billing_flags(None, self._schema_editor())

        self.assertEqual(self._flags(1), (True, False))
        self.assertEqual(self._flags(2), (False, True))

    def test_corrective_migration_ignores_noncurrent_distinct_billing_row(self) -> None:
        self.database.executemany(
            """
            INSERT INTO customer_addresses
                (id, customer_id, address_type, is_primary, is_billing, is_current)
            VALUES (?, ?, '', ?, ?, ?)
            """,
            [
                (1, 100, True, True, True),
                (2, 100, False, True, False),
            ],
        )
        migration = importlib.import_module(
            "apps.customers.migrations.0021_repair_address_billing_flags"
        )

        migration.repair_address_billing_flags(None, self._schema_editor())

        self.assertEqual(self._flags(1), (True, True))
