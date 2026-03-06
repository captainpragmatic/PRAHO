"""Clear e-Factura OAuth tokens for AES-256-GCM encryption upgrade.

Tokens encrypted with Django Signer become unreadable.
OAuth must be re-authenticated after this migration.
"""

from django.db import migrations


def clear_efactura_tokens(apps, schema_editor):
    """Clear encrypted OAuth tokens."""
    OAuthToken = apps.get_model("billing", "OAuthToken")
    updated = OAuthToken.objects.all().update(
        access_token="",
        refresh_token="",
    )
    if updated:
        print(f"\n  Cleared {updated} OAuth token(s). Re-authenticate e-Factura.")


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0016_alter_oauthtoken_options"),
    ]

    operations = [
        migrations.RunPython(clear_efactura_tokens, migrations.RunPython.noop),
    ]
