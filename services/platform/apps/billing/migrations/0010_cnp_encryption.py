"""Encrypt the invoice and proforma CNP snapshots at rest, bound to each row (ADR-0040).

Generated, then the trigger steps appended. They run last because SQLite drops a table's
triggers whenever Django rebuilds the table, which the changes above do. The one-fiscal-id
constraints now test the CNP for NULL, which is how an empty CNP is stored. Existing databases
are rebuilt (ADR-0052): the unique context ids have no per-row backfill.
"""

import uuid
from typing import Any

from django.conf import settings
from django.db import migrations, models

import apps.common.cnp_validator
import apps.common.fields
from apps.common.db_triggers import create_context_immutability_trigger, drop_context_immutability_trigger

_TRIGGERS = (
    ("billing_invoices", "billing_invoice_encryption_context_immutable"),
    ("billing_proforma_invoices", "billing_proforma_encryption_context_immutable"),
)


def create_triggers(apps: Any, schema_editor: Any) -> None:
    for table, name in _TRIGGERS:
        create_context_immutability_trigger(schema_editor, table=table, column="encryption_context_id", name=name)


def drop_triggers(apps: Any, schema_editor: Any) -> None:
    for table, name in _TRIGGERS:
        drop_context_immutability_trigger(schema_editor, table=table, name=name)


class Migration(migrations.Migration):

    dependencies = [
        ('billing', '0009_runtime_grace_defaults'),
        ('customers', '0004_cnp_encryption'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='invoice',
            name='invoice_one_fiscal_id',
        ),
        migrations.RemoveConstraint(
            model_name='proformainvoice',
            name='proforma_one_fiscal_id',
        ),
        migrations.AddField(
            model_name='invoice',
            name='encryption_context_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AddField(
            model_name='proformainvoice',
            name='encryption_context_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AlterField(
            model_name='invoice',
            name='bill_to_cnp',
            field=apps.common.fields.EncryptedTextField(aad_context_field='encryption_context_id', blank=True, help_text='Romanian personal fiscal identifier snapshotted when the invoice is created', max_length=13, null=True, require_v2=True, validators=[apps.common.cnp_validator.validate_cnp]),
        ),
        migrations.AlterField(
            model_name='proformainvoice',
            name='bill_to_cnp',
            field=apps.common.fields.EncryptedTextField(aad_context_field='encryption_context_id', blank=True, help_text='Romanian personal fiscal identifier snapshotted when the proforma is created', max_length=13, null=True, require_v2=True, validators=[apps.common.cnp_validator.validate_cnp]),
        ),
        migrations.AddConstraint(
            model_name='invoice',
            constraint=models.CheckConstraint(condition=models.Q(('bill_to_tax_id', ''), ('bill_to_cnp__isnull', True), _connector='OR'), name='invoice_one_fiscal_id'),
        ),
        migrations.AddConstraint(
            model_name='proformainvoice',
            constraint=models.CheckConstraint(condition=models.Q(('bill_to_tax_id', ''), ('bill_to_cnp__isnull', True), _connector='OR'), name='proforma_one_fiscal_id'),
        ),
        migrations.RunPython(create_triggers, drop_triggers),
    ]
