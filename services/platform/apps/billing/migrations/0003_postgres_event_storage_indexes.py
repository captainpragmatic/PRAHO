"""GIN, partial covering and BRIN indexes on usage events and invoices, PostgreSQL only.

The models also run on SQLite, so these PostgreSQL-specific indexes live
in a vendor-gated migration instead of Meta.indexes and stay outside
Django's model state. Carried forward verbatim from billing 0002 of the old history
(ADR-0052). SQLite gets nothing.
"""

from typing import Any

from django.db import migrations


def apply_postgres_event_storage_indexes(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return

    statements = (
        """
        CREATE INDEX IF NOT EXISTS billing_usage_events_properties_gin
        ON billing_usage_events USING GIN (properties);
        """,
        """
        CREATE INDEX IF NOT EXISTS billing_invoices_efactura_response_gin
        ON billing_invoices USING GIN (efactura_response);
        """,
        """
        CREATE INDEX IF NOT EXISTS billing_usage_events_pending_cover_idx
        ON billing_usage_events (is_processed, timestamp DESC)
        INCLUDE (meter_id, customer_id, subscription_id, aggregation_id, value, source, processed_at)
        WHERE is_processed = false;
        """,
        """
        CREATE INDEX IF NOT EXISTS billing_usage_events_timestamp_brin
        ON billing_usage_events USING BRIN (timestamp) WITH (pages_per_range = 32);
        """,
    )
    with schema_editor.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def reverse_postgres_event_storage_indexes(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return

    statements = (
        "DROP INDEX IF EXISTS billing_usage_events_timestamp_brin;",
        "DROP INDEX IF EXISTS billing_usage_events_pending_cover_idx;",
        "DROP INDEX IF EXISTS billing_invoices_efactura_response_gin;",
        "DROP INDEX IF EXISTS billing_usage_events_properties_gin;",
    )
    with schema_editor.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0002_initial"),
    ]

    operations = [
        migrations.RunPython(apply_postgres_event_storage_indexes, reverse_postgres_event_storage_indexes),
    ]
