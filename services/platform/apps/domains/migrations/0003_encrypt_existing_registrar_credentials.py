from django.db import migrations


def encrypt_existing_credentials(apps, schema_editor):
    Registrar = apps.get_model('domains', 'Registrar')
    # Lazy import encryption utils (not available via apps registry)
    from apps.common.encryption import decrypt_sensitive_data, encrypt_sensitive_data

    for registrar in Registrar.objects.all():
        updated_fields = []

        # api_key
        if registrar.api_key:
            decrypted = decrypt_sensitive_data(registrar.api_key)
            # If decryption failed but value exists, assume plaintext and encrypt
            if not decrypted:
                registrar.api_key = encrypt_sensitive_data(registrar.api_key)
                updated_fields.append('api_key')

        # api_secret
        if registrar.api_secret:
            decrypted = decrypt_sensitive_data(registrar.api_secret)
            if not decrypted:
                registrar.api_secret = encrypt_sensitive_data(registrar.api_secret)
                updated_fields.append('api_secret')

        if updated_fields:
            registrar.save(update_fields=updated_fields)


class Migration(migrations.Migration):
    dependencies = [
        ('domains', '0002_add_performance_indexes'),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_credentials, migrations.RunPython.noop),
    ]

