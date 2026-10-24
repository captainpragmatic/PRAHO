"""Bind each vault credential to the service and identifier that find it (#751 follow-up, M19).

Re-encrypts existing ciphertext from the row-and-field AAD to one that also carries (service_type,
service_identifier), and back on reverse. The formulas are frozen in apps.common.secret_rebind. A credential
that opens under neither aborts the migration with nothing changed: a wrong CREDENTIAL_VAULT_MASTER_KEY
looks exactly like a wrong AAD. Run it with the platform and its workers stopped: a process still running the
previous release writes the old formula (``manage.py rebind_secrets`` re-binds anything written meanwhile).
"""

import logging

from django.conf import settings
from django.db import migrations

from apps.common.secret_rebind import rebind_vault

logger = logging.getLogger(__name__)


def _rebind(apps, schema_editor, *, forward):
    model = apps.get_model("common", "EncryptedCredential")
    key = getattr(settings, "CREDENTIAL_VAULT_MASTER_KEY", None)
    counts = rebind_vault(model, schema_editor.connection.alias, key, forward=forward)
    if counts.superseded:
        logger.warning("⚠️ [Vault] %s credential values are in a superseded format: store them again", counts.superseded)


def bind_natural_key(apps, schema_editor):
    _rebind(apps, schema_editor, forward=True)


def unbind_natural_key(apps, schema_editor):
    _rebind(apps, schema_editor, forward=False)


class Migration(migrations.Migration):
    dependencies = [
        ("common", "0004_persistent_secret_contexts"),
    ]

    operations = [
        migrations.RunPython(bind_natural_key, unbind_natural_key),
    ]
