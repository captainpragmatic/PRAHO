"""Database objects that exist only because a hand-written migration creates them.

Django's model state does not know about these, so neither makemigrations
nor the model tests notice if a migration that creates them goes missing:
- nine PostgreSQL-only indexes (audit 0003, billing 0003, integrations 0002);
- the encryption-context functions and triggers: payment methods (customers 0003), tax
  profiles (customers 0004), invoices and proformas (billing 0010).

The test branches on the backend instead of skipping: PostgreSQL must have
all of them, SQLite must have the triggers and none of the indexes, and any
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
# trigger (and, on PostgreSQL, function) name -> table
TRIGGERS: dict[str, str] = {
    "customer_payment_method_encryption_context_immutable": "customer_payment_methods",
    "customer_tax_profile_encryption_context_immutable": "customer_tax_profiles",
    "billing_invoice_encryption_context_immutable": "billing_invoices",
    "billing_proforma_encryption_context_immutable": "billing_proforma_invoices",
    "secret_ctx_users_user": "users",
    "secret_ctx_domains_registrar": "domain_registrars",
    "secret_ctx_domains_domainorderitem": "domain_order_items",
    "secret_ctx_domains_domain": "domains",
    "secret_ctx_provisioning_server": "provisioning_servers",
    "secret_ctx_provisioning_virtualminserver": "provisioning_virtualmin_servers",
    "secret_ctx_provisioning_virtualminaccount": "provisioning_virtualmin_accounts",
    "secret_ctx_settings_systemsetting": "setting_entries",
    "secret_ctx_billing_oauthtoken": "billing_efactura_oauth_tokens",
    "secret_ctx_notifications_emaillog": "notification_email_logs",
    "secret_ctx_notifications_emailsuppression": "notification_email_suppressions",
    "secret_ctx_common_encryptedcredential": "common_credentials",
}


class MigrationOnlyDatabaseObjectsTests(TestCase):
    def test_processing_state_comments_are_installed_on_postgresql(self) -> None:
        if connection.vendor != "postgresql":
            return  # SQLite has no database column-comment feature.
        with connection.cursor() as cursor:
            for table, column, expected in (
                ("notification_email_logs", "delivery_attempts", "Durable count of claimed provider sends"),
                ("integration_webhook_events", "staff_alerted_at", "First committed staff alert"),
            ):
                with self.subTest(column=column):
                    cursor.execute(
                        "SELECT col_description(c.oid, a.attnum) FROM pg_class c "
                        "JOIN pg_attribute a ON a.attrelid = c.oid "
                        "JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE c.relname = %s AND a.attname = %s AND n.nspname = current_schema()",
                        [table, column],
                    )
                    self.assertIn(expected, cursor.fetchone()[0])

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

    def test_encryption_context_triggers_exist(self) -> None:
        with connection.cursor() as cursor:
            for trigger, table in TRIGGERS.items():
                with self.subTest(trigger=trigger):
                    if connection.vendor == "postgresql":
                        cursor.execute(
                            "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                            "WHERE t.tgname = %s AND c.relname = %s AND NOT t.tgisinternal",
                            [trigger, table],
                        )
                        self.assertEqual(cursor.fetchone()[0], 1)
                        cursor.execute("SELECT count(*) FROM pg_proc WHERE proname = %s", [trigger])
                        self.assertEqual(cursor.fetchone()[0], 1)
                    elif connection.vendor == "sqlite":
                        cursor.execute(
                            "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = %s AND tbl_name = %s",
                            [trigger, table],
                        )
                        self.assertEqual(cursor.fetchone()[0], 1)
                    else:
                        self.fail(f"unsupported database backend: {connection.vendor}")
