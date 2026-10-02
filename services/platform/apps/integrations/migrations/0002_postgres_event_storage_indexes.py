"""Covering, opclass and BRIN indexes on webhook events, PostgreSQL only.

The models also run on SQLite, so these PostgreSQL-specific indexes live
in a vendor-gated migration instead of Meta.indexes and stay outside
Django's model state. Carried forward verbatim from integrations 0001 of
the old history (ADR-0052). SQLite gets nothing.
"""

from typing import Any

from django.db import migrations


def apply_postgres_event_storage_indexes(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return

    statements = (
        """
        CREATE INDEX IF NOT EXISTS integration_webhook_events_recent_cover_idx
        ON integration_webhook_events (received_at DESC)
        INCLUDE (source, event_type, status, processed_at, retry_count, next_retry_at);
        """,
        """
        CREATE INDEX IF NOT EXISTS integration_webhook_events_efactura_lookup_idx
        ON integration_webhook_events (source, event_id varchar_pattern_ops, received_at DESC)
        INCLUDE (status, processed_at, error_message);
        """,
        """
        CREATE INDEX IF NOT EXISTS integration_webhook_events_received_at_brin
        ON integration_webhook_events USING BRIN (received_at) WITH (pages_per_range = 32);
        """,
    )
    with schema_editor.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def reverse_postgres_event_storage_indexes(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return

    statements = (
        "DROP INDEX IF EXISTS integration_webhook_events_received_at_brin;",
        "DROP INDEX IF EXISTS integration_webhook_events_efactura_lookup_idx;",
        "DROP INDEX IF EXISTS integration_webhook_events_recent_cover_idx;",
    )
    with schema_editor.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


class Migration(migrations.Migration):
    dependencies = [
        ("integrations", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(apply_postgres_event_storage_indexes, reverse_postgres_event_storage_indexes),
    ]
