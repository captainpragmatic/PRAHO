from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_rename_webauthn_cr_user_id_e94f82_idx_idx_tfa_webauthn_user_created_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='webauthncredential',
            name='credential_id',
            field=models.TextField(),
        ),
        migrations.AddField(
            model_name='webauthncredential',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='webauthncredential',
            name='transport',
            field=models.CharField(blank=True, choices=[('usb', 'USB'), ('nfc', 'NFC'), ('ble', 'Bluetooth Low Energy'), ('internal', 'Internal (Touch ID, Face ID)'), ('hybrid', 'Hybrid')], default='', max_length=20),
        ),
        migrations.AddField(
            model_name='webauthncredential',
            name='metadata',
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddConstraint(
            model_name='webauthncredential',
            constraint=models.UniqueConstraint(fields=('user', 'credential_id'), name='uniq_user_credential'),
        ),
        migrations.AddIndex(
            model_name='webauthncredential',
            index=models.Index(fields=['user', 'is_active'], name='idx_tfa_webauthn_user_active'),
        ),
    ]

