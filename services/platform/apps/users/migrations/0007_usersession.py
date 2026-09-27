"""Backfill the revocation index for sessions created before the indexed store."""

from itertools import islice

import django.db.models.deletion
from django.apps.registry import Apps
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.db import migrations, models
from django.db.backends.base.schema import BaseDatabaseSchemaEditor


def backfill_user_sessions(apps: Apps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    session_model = apps.get_model("sessions", "Session")
    user_model = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    index_model = apps.get_model("users", "UserSession")
    alias = schema_editor.connection.alias
    decoder = SessionStore()
    sessions = session_model.objects.using(alias).order_by("session_key").iterator(chunk_size=500)

    while batch := list(islice(sessions, 500)):
        owners: dict[str, int] = {}
        for session in batch:
            data = decoder.decode(session.session_data)
            user_id = data.get("_auth_user_id") if isinstance(data, dict) else None
            # login() stores the primary key as a string of digits; anything else is not ours.
            if isinstance(user_id, str) and user_id.isdigit():
                owners[session.session_key] = int(user_id)
        existing = set(user_model.objects.using(alias).filter(pk__in=set(owners.values())).values_list("pk", flat=True))
        entries = [index_model(user_id=uid, session_key=key) for key, uid in owners.items() if uid in existing]
        index_model.objects.using(alias).bulk_create(entries, batch_size=500, ignore_conflicts=True)


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0006_localisation_inheritance"),
        ("sessions", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserSession",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("session_key", models.CharField(max_length=40, unique=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        db_constraint=False,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="session_index",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.RunPython(backfill_user_sessions, migrations.RunPython.noop),
    ]
