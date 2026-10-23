"""A partial index for chain recovery's scan of pending events, PostgreSQL only (#751 follow-up, M16).

Recovery runs every minute and selects events whose metadata marks them pending a chain link, oldest
first. Without this index every run scanned the whole audit table. The predicate matches the ORM's
``metadata__chain_link_pending=True`` lookup so the planner can use it. Vendor-gated like 0003: the models
also run on SQLite, which gets nothing.
"""

from typing import Any

from django.db import migrations


def apply_chain_pending_index(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS audit_events_chain_pending_idx
            ON audit_events (timestamp, id)
            WHERE (metadata -> 'chain_link_pending') = 'true'::jsonb;
            """
        )


def reverse_chain_pending_index(apps: Any, schema_editor: Any) -> None:
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DROP INDEX IF EXISTS audit_events_chain_pending_idx;")


class Migration(migrations.Migration):
    dependencies = [
        ("audit", "0014_email_provider_blocked_action"),
    ]

    operations = [
        migrations.RunPython(apply_chain_pending_index, reverse_chain_pending_index),
    ]
