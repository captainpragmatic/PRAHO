"""Allocate immutable contexts without rewriting or removing existing secrets."""

import uuid

from django.db import migrations, models

from apps.common.db_triggers import create_context_immutability_trigger, drop_context_immutability_trigger

CONTEXT_MODELS = ["SystemSetting"]
IDENTITY_MODELS = []


def populate_contexts(apps, schema_editor):
    alias = schema_editor.connection.alias
    for model_name in CONTEXT_MODELS:
        Model = apps.get_model(APP, model_name)
        for row in Model.objects.using(alias).filter(encryption_context_id__isnull=True).iterator(chunk_size=1000):
            Model.objects.using(alias).filter(pk=row.pk).update(encryption_context_id=uuid.uuid4())


def install_guards(apps, schema_editor):
    for model_name in CONTEXT_MODELS + IDENTITY_MODELS:
        Model = apps.get_model(APP, model_name)
        column = "encryption_context_id" if model_name in CONTEXT_MODELS else Model._meta.pk.column
        create_context_immutability_trigger(
            schema_editor, table=Model._meta.db_table, column=column, name=f"secret_ctx_{APP}_{model_name.lower()}"
        )


def remove_guards(apps, schema_editor):
    for model_name in CONTEXT_MODELS + IDENTITY_MODELS:
        Model = apps.get_model(APP, model_name)
        drop_context_immutability_trigger(
            schema_editor, table=Model._meta.db_table, name=f"secret_ctx_{APP}_{model_name.lower()}"
        )


APP = "settings"


class Migration(migrations.Migration):
    dependencies = [("settings", "0003_setting_activation")]
    operations = [
        migrations.AddField(
            model_name="systemsetting", name="encryption_context_id", field=models.UUIDField(null=True, editable=False)
        ),
        migrations.RunPython(populate_contexts, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="systemsetting",
            name="encryption_context_id",
            field=models.UUIDField(default=uuid.uuid4, unique=True, editable=False),
        ),
        migrations.RunPython(install_guards, remove_guards),
    ]
