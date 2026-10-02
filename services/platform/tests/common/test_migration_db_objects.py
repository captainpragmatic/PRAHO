"""Database objects that exist only because a hand-written migration creates them.

Django's model state does not know about these, so neither makemigrations
nor the model tests notice if a migration that creates them goes missing:
- nine PostgreSQL-only indexes (audit 0003, billing 0003, integrations 0002);
- the payment-method encryption-context function and trigger (customers 0003).

The test branches on the backend instead of skipping: PostgreSQL must have
all of them, SQLite must have the trigger and none of the indexes, and any
other backend fails, as the trigger migration itself does.
"""

from __future__ import annotations

from django.db import connection
from django.test import TestCase

# table -> {index name: a fragment its definition must contain}
POSTGRES_INDEXES: dict[str, dict[str, str]] = {
    "audit_events": {
        "audit_events_dashboard_cover_idx": "INCLUDE (user_id, action, category",
        "audit_events_timestamp_brin": "USING brin",
    },
    "billing_usage_events": {
        "billing_usage_events_properties_gin": "USING gin (properties)",
        "billing_usage_events_pending_cover_idx": "WHERE (is_processed = false)",
        "billing_usage_events_timestamp_brin": "USING brin",
    },
    "billing_invoices": {
        "billing_invoices_efactura_response_gin": "USING gin (efactura_response)",
    },
    "integration_webhook_events": {
        "integration_webhook_events_recent_cover_idx": "INCLUDE (source, event_type, status",
        "integration_webhook_events_efactura_lookup_idx": "event_id varchar_pattern_ops",
        "integration_webhook_events_received_at_brin": "USING brin",
    },
}
TRIGGER = "customer_payment_method_encryption_context_immutable"
TRIGGER_TABLE = "customer_payment_methods"


class MigrationOnlyDatabaseObjectsTests(TestCase):
    def _index_names(self, table: str) -> set[str]:
        with connection.cursor() as cursor:
            return set(connection.introspection.get_constraints(cursor, table))

    def test_postgresql_indexes_match_the_backend(self) -> None:
        self.assertEqual(sum(len(indexes) for indexes in POSTGRES_INDEXES.values()), 9)
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                for table, indexes in POSTGRES_INDEXES.items():
                    cursor.execute("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = %s", [table])
                    definitions = dict(cursor.fetchall())
                    for name, fragment in indexes.items():
                        with self.subTest(index=name):
                            self.assertIn(name, definitions)
                            self.assertIn(fragment, definitions[name])
        elif connection.vendor == "sqlite":
            for table, indexes in POSTGRES_INDEXES.items():
                with self.subTest(table=table):
                    self.assertEqual(self._index_names(table) & set(indexes), set())
        else:
            self.fail(f"unsupported database backend: {connection.vendor}")

    def test_encryption_context_trigger_exists(self) -> None:
        with connection.cursor() as cursor:
            if connection.vendor == "postgresql":
                cursor.execute(
                    "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                    "WHERE t.tgname = %s AND c.relname = %s AND NOT t.tgisinternal",
                    [TRIGGER, TRIGGER_TABLE],
                )
                self.assertEqual(cursor.fetchone()[0], 1)
                cursor.execute("SELECT count(*) FROM pg_proc WHERE proname = %s", [TRIGGER])
                self.assertEqual(cursor.fetchone()[0], 1)
            elif connection.vendor == "sqlite":
                cursor.execute(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = %s AND tbl_name = %s",
                    [TRIGGER, TRIGGER_TABLE],
                )
                self.assertEqual(cursor.fetchone()[0], 1)
            else:
                self.fail(f"unsupported database backend: {connection.vendor}")
