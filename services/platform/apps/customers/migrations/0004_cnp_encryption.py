"""Encrypt the tax profile's CNP at rest, bound to the row (ADR-0040).

Generated, then the trigger step appended. It runs last because SQLite drops a table's triggers
whenever Django rebuilds the table, which the field change above does. Existing databases are
rebuilt (ADR-0052): the unique context id has no per-row backfill.
"""

import uuid
from typing import Any

from django.db import migrations, models

import apps.common.cnp_validator
import apps.common.fields
from apps.common.db_triggers import create_context_immutability_trigger, drop_context_immutability_trigger


def create_trigger(apps: Any, schema_editor: Any) -> None:
    create_context_immutability_trigger(
        schema_editor,
        table="customer_tax_profiles",
        column="encryption_context_id",
        name="customer_tax_profile_encryption_context_immutable",
    )


def drop_trigger(apps: Any, schema_editor: Any) -> None:
    drop_context_immutability_trigger(
        schema_editor, table="customer_tax_profiles", name="customer_tax_profile_encryption_context_immutable"
    )


class Migration(migrations.Migration):

    dependencies = [
        ('customers', '0003_payment_method_encryption_context_trigger'),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name='customertaxprofile',
            name='customer_ta_cnp_f1a5ad_idx',
        ),
        migrations.AddField(
            model_name='customertaxprofile',
            name='encryption_context_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AlterField(
            model_name='customertaxprofile',
            name='cnp',
            field=apps.common.fields.EncryptedTextField(aad_context_field='encryption_context_id', blank=True, help_text='Cod Numeric Personal (13 cifre)', max_length=13, null=True, require_v2=True, validators=[apps.common.cnp_validator.validate_cnp], verbose_name='CNP'),
        ),
        migrations.RunPython(create_trigger, drop_trigger),
    ]
