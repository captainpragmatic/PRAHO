"""Clear credential vault data for AES-256-GCM encryption upgrade.

Fernet-encrypted vault credentials become unreadable after key format change.
All credentials must be re-seeded.
"""

from django.db import migrations


def clear_vault_credentials(apps, schema_editor):
    """Delete all encrypted credentials (Fernet-encrypted, now unreadable)."""
    EncryptedCredential = apps.get_model("common", "EncryptedCredential")
    count = EncryptedCredential.objects.count()
    if count:
        EncryptedCredential.objects.all().delete()
        print(f"\n  Deleted {count} vault credential(s). Re-seed with setup_credential_vault.")


class Migration(migrations.Migration):
    dependencies = [
        ("common", "0003_alter_encryptedcredential_service_type"),
    ]

    operations = [
        migrations.RunPython(clear_vault_credentials, migrations.RunPython.noop),
    ]
