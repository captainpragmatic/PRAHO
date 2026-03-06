"""
Encrypt Server management credentials at rest — field size + data wipe.

Part of AES-256-GCM encryption consolidation (ADR-0033).
Clears all existing plaintext Server management credentials (must be re-entered).
"""

from django.db import migrations, models


def clear_plaintext_server_credentials(apps, schema_editor):
    """Wipe plaintext server management credentials."""
    Server = apps.get_model("provisioning", "Server")
    count = Server.objects.filter(
        models.Q(management_api_key__gt="")
        | models.Q(management_api_secret__gt="")
        | models.Q(management_webhook_secret__gt="")
    ).update(management_api_key="", management_api_secret="", management_webhook_secret="")
    if count:
        print(f"  Cleared management credentials on {count} server(s) — re-enter via admin")


class Migration(migrations.Migration):
    dependencies = [
        ("provisioning", "0016_clear_encrypted_passwords"),
    ]

    operations = [
        # Increase max_length on webhook_secret for ciphertext overhead
        migrations.AlterField(
            model_name="server",
            name="management_webhook_secret",
            field=models.CharField(
                blank=True, default="", max_length=500, verbose_name="AES-256-GCM Encrypted Webhook Secret"
            ),
        ),
        # Wipe existing plaintext data
        migrations.RunPython(clear_plaintext_server_credentials, migrations.RunPython.noop),
    ]
