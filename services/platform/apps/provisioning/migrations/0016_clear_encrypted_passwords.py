"""Clear encrypted passwords for AES-256-GCM encryption upgrade.

Fernet-encrypted server and account passwords become unreadable.
Credentials must be re-entered after this migration.
"""

from django.db import migrations


def clear_encrypted_passwords(apps, schema_editor):
    """Clear encrypted password fields on VirtualminServer and HostingAccount.

    These models were removed in a later migration. The try/except handles
    running this migration on a fresh database where they never existed.
    """
    servers = 0
    accounts = 0
    try:
        VirtualminServer = apps.get_model("provisioning", "VirtualminServer")
        servers = VirtualminServer.objects.exclude(encrypted_api_password=b"").update(
            encrypted_api_password=b"",
        )
    except LookupError:
        pass
    try:
        HostingAccount = apps.get_model("provisioning", "HostingAccount")
        accounts = HostingAccount.objects.exclude(encrypted_password=b"").update(
            encrypted_password=b"",
        )
    except LookupError:
        pass
    if servers or accounts:
        print(f"\n  Cleared passwords: {servers} server(s), {accounts} account(s). Re-enter credentials.")


class Migration(migrations.Migration):
    dependencies = [
        ("provisioning", "0015_alter_virtualminprovisioningjob_rollback_status"),
    ]

    operations = [
        migrations.RunPython(clear_encrypted_passwords, migrations.RunPython.noop),
    ]
