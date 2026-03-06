"""
Encrypt domain credentials at rest — field size increase + data wipe.

Part of AES-256-GCM encryption consolidation (ADR-0033).
Increases max_length on encrypted fields to accommodate ciphertext overhead,
and clears all existing plaintext credentials (must be re-entered).
"""

from django.db import migrations, models


def clear_plaintext_credentials(apps, schema_editor):
    """Wipe all plaintext registrar credentials and EPP codes.

    These were stored unencrypted. After this migration, all credentials
    must be re-entered through the admin form (which encrypts on save).
    """
    Registrar = apps.get_model("domains", "Registrar")
    count = Registrar.objects.filter(
        models.Q(api_key__gt="") | models.Q(api_secret__gt="") | models.Q(webhook_secret__gt="")
    ).update(api_key="", api_secret="", webhook_secret="")
    if count:
        print(f"  Cleared credentials on {count} registrar(s) — re-enter via admin")

    Domain = apps.get_model("domains", "Domain")
    epp_count = Domain.objects.filter(epp_code__gt="").update(epp_code="")
    if epp_count:
        print(f"  Cleared EPP codes on {epp_count} domain(s)")

    DomainOrderItem = apps.get_model("domains", "DomainOrderItem")
    order_epp_count = DomainOrderItem.objects.filter(epp_code__gt="").update(epp_code="")
    if order_epp_count:
        print(f"  Cleared EPP codes on {order_epp_count} domain order item(s)")


class Migration(migrations.Migration):
    dependencies = [
        ("domains", "0002_initial"),
    ]

    operations = [
        # Increase max_length to accommodate AES-256-GCM ciphertext
        migrations.AlterField(
            model_name="registrar",
            name="api_key",
            field=models.CharField(blank=True, help_text="AES-256-GCM encrypted", max_length=500),
        ),
        migrations.AlterField(
            model_name="registrar",
            name="api_secret",
            field=models.CharField(blank=True, help_text="AES-256-GCM encrypted", max_length=500),
        ),
        migrations.AlterField(
            model_name="registrar",
            name="webhook_secret",
            field=models.CharField(
                blank=True, help_text="AES-256-GCM encrypted — webhook signature verification", max_length=500
            ),
        ),
        migrations.AlterField(
            model_name="domain",
            name="epp_code",
            field=models.CharField(
                blank=True, help_text="AES-256-GCM encrypted EPP/Auth code for transfers", max_length=300
            ),
        ),
        migrations.AlterField(
            model_name="domainorderitem",
            name="epp_code",
            field=models.CharField(
                blank=True, help_text="AES-256-GCM encrypted EPP/Auth code for domain transfer", max_length=300
            ),
        ),
        # Wipe existing plaintext data
        migrations.RunPython(clear_plaintext_credentials, migrations.RunPython.noop),
    ]
