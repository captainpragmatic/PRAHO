"""Covering and BRIN indexes on audit_events, PostgreSQL only.

The models also run on SQLite, so these PostgreSQL-specific indexes live
in a vendor-gated migration instead of Meta.indexes and stay outside
Django's model state. Carried forward verbatim from audit 0002 of the old history
(ADR-0052). SQLite gets nothing.
"""

from typing import Any

from django.db import migrations


def apply_postgres_event_storage_indexes(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return

    statements = (
        """
        CREATE INDEX IF NOT EXISTS audit_events_dashboard_cover_idx
        ON audit_events (timestamp DESC)
        INCLUDE (user_id, action, category, severity, actor_type, content_type_id, object_id, request_id, is_sensitive, requires_review);
        """,
        """
        CREATE INDEX IF NOT EXISTS audit_events_timestamp_brin
        ON audit_events USING BRIN (timestamp) WITH (pages_per_range = 32);
        """,
    )
    with schema_editor.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


def reverse_postgres_event_storage_indexes(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return

    statements = (
        "DROP INDEX IF EXISTS audit_events_timestamp_brin;",
        "DROP INDEX IF EXISTS audit_events_dashboard_cover_idx;",
    )
    with schema_editor.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


class Migration(migrations.Migration):
    dependencies = [
        ("audit", "0002_initial"),
    ]

    operations = [
        migrations.RunPython(apply_postgres_event_storage_indexes, reverse_postgres_event_storage_indexes),
    ]
