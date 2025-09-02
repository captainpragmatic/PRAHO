# Generated migration for Credential Vault models

import uuid
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_encrypt_2fa_secrets'),
    ]

    operations = [
        migrations.CreateModel(
            name='EncryptedCredential',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('service_type', models.CharField(choices=[('virtualmin', 'Virtualmin API'), ('stripe', 'Stripe Payment Gateway'), ('dns_cloudflare', 'Cloudflare DNS'), ('dns_route53', 'AWS Route53 DNS'), ('ssh', 'SSH Access'), ('ssl_certificate', 'SSL Certificate'), ('backup_storage', 'Backup Storage'), ('monitoring', 'Monitoring Service'), ('email_smtp', 'SMTP Email Service'), ('domain_registrar', 'Domain Registrar')], max_length=50)),
                ('service_identifier', models.CharField(help_text='Server hostname, account ID, or unique identifier', max_length=255)),
                ('encrypted_username', models.BinaryField()),
                ('encrypted_password', models.BinaryField()),
                ('encrypted_metadata', models.BinaryField(blank=True, help_text='Additional encrypted data (API keys, certificates, etc.)', null=True)),
                ('expires_at', models.DateTimeField()),
                ('rotation_count', models.PositiveIntegerField(default=0)),
                ('last_accessed', models.DateTimeField(blank=True, null=True)),
                ('access_count', models.PositiveIntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('rotation_in_progress', models.BooleanField(default=False)),
                ('last_rotation_attempt', models.DateTimeField(blank=True, null=True)),
                ('rotation_failure_count', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'credential_vault_credentials',
            },
        ),
        migrations.CreateModel(
            name='CredentialAccessLog',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('username', models.CharField(help_text='Username at time of access (for audit trail)', max_length=255)),
                ('access_reason', models.CharField(help_text='Reason for credential access', max_length=255)),
                ('source_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True)),
                ('access_method', models.CharField(choices=[('api', 'API Access'), ('admin', 'Admin Interface'), ('task', 'Background Task'), ('migration', 'Data Migration'), ('rotation', 'Credential Rotation')], max_length=50)),
                ('success', models.BooleanField(default=True)),
                ('error_message', models.TextField(blank=True)),
                ('accessed_at', models.DateTimeField(auto_now_add=True)),
                ('credential', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='access_logs', to='common.encryptedcredential')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='users.user')),
            ],
            options={
                'db_table': 'credential_vault_access_logs',
            },
        ),
        migrations.AddIndex(
            model_name='encryptedcredential',
            index=models.Index(fields=['service_type', 'service_identifier'], name='credential_vault_credentials_service_type_service_id_idx'),
        ),
        migrations.AddIndex(
            model_name='encryptedcredential',
            index=models.Index(fields=['expires_at'], name='credential_vault_credentials_expires_at_idx'),
        ),
        migrations.AddIndex(
            model_name='encryptedcredential',
            index=models.Index(fields=['last_accessed'], name='credential_vault_credentials_last_accessed_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='encryptedcredential',
            unique_together={('service_type', 'service_identifier')},
        ),
        migrations.AddIndex(
            model_name='credentialaccesslog',
            index=models.Index(fields=['credential', 'accessed_at'], name='credential_vault_access_logs_credential_accessed_at_idx'),
        ),
        migrations.AddIndex(
            model_name='credentialaccesslog',
            index=models.Index(fields=['user', 'accessed_at'], name='credential_vault_access_logs_user_accessed_at_idx'),
        ),
        migrations.AddIndex(
            model_name='credentialaccesslog',
            index=models.Index(fields=['accessed_at'], name='credential_vault_access_logs_accessed_at_idx'),
        ),
    ]
