"""Bind each server's API password to its hostname (#751 follow-up, M19).

Re-encrypts VirtualminServer.encrypted_api_password and Server._api_password_encrypted from the row-and-field
AAD to one that also carries the hostname, and back on reverse (formulas frozen in apps.common.secret_rebind).
A value that opens under neither aborts with nothing changed; a keyring that lacks the key raises. Run it with
the platform and its workers stopped (``manage.py rebind_secrets`` re-binds anything written meanwhile).
"""

import logging

from django.db import migrations

from apps.common.secret_rebind import HostnamePassword, rebind_hostname_passwords

logger = logging.getLogger(__name__)


def _rebind(apps, schema_editor, *, forward):
    alias = schema_editor.connection.alias
    virtualmin = apps.get_model("provisioning", "VirtualminServer")
    server = apps.get_model("provisioning", "Server")
    # Each row stays locked from its read to its write: a password stored meanwhile is not overwritten
    for counts in (
        rebind_hostname_passwords(
            HostnamePassword(virtualmin, "encrypted_api_password", lambda row: row.pk, binary=True), alias, forward=forward, lock=True
        ),
        rebind_hostname_passwords(
            HostnamePassword(server, "_api_password_encrypted", lambda row: row.encryption_context_id, binary=False),
            alias,
            forward=forward, lock=True,
        ),
    ):
        if counts.superseded:
            logger.warning("⚠️ [Provisioning] %s server API passwords are in a superseded format: enter them again", counts.superseded)


def bind_hostname(apps, schema_editor):
    _rebind(apps, schema_editor, forward=True)


def unbind_hostname(apps, schema_editor):
    _rebind(apps, schema_editor, forward=False)


class Migration(migrations.Migration):
    dependencies = [
        ("provisioning", "0011_persistent_secret_contexts"),
    ]

    operations = [
        migrations.RunPython(bind_hostname, unbind_hostname),
    ]
