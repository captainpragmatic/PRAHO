"""Clear 2FA data for AES-256-GCM encryption upgrade.

All Fernet-encrypted 2FA secrets become unreadable after the key format change.
Users must re-enroll in 2FA after this migration.
"""

from django.db import migrations


def clear_2fa_data(apps, schema_editor):
    """Disable 2FA and clear encrypted secrets for all users."""
    User = apps.get_model("users", "User")
    updated = User.objects.filter(two_factor_enabled=True).update(
        _two_factor_secret="",
        two_factor_enabled=False,
        backup_tokens=[],
    )
    if updated:
        print(f"\n  Cleared 2FA data for {updated} user(s). They must re-enroll.")


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(clear_2fa_data, migrations.RunPython.noop),
    ]
