# Custom migration to encrypt existing 2FA secrets
# Generated manually for PRAHO Platform 2FA security improvements

from django.db import migrations, models
import os


def encrypt_existing_2fa_secrets(apps, schema_editor):
    """Encrypt existing plain-text 2FA secrets"""
    User = apps.get_model('users', 'User')
    
    # Only encrypt if we have an encryption key
    encryption_key = os.environ.get('DJANGO_ENCRYPTION_KEY')
    if not encryption_key:
        # In development/testing, we might not have encryption key yet
        # Just clear secrets - users will need to re-setup 2FA
        print("WARNING: No DJANGO_ENCRYPTION_KEY found. Clearing existing 2FA secrets.")
        User.objects.filter(two_factor_enabled=True).update(
            two_factor_secret='',
            two_factor_enabled=False,
            backup_tokens=[]
        )
        return
    
    from cryptography.fernet import Fernet
    import base64
    
    try:
        key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        fernet = Fernet(key)
        
        # Encrypt existing secrets
        for user in User.objects.filter(two_factor_enabled=True, two_factor_secret__isnull=False).exclude(two_factor_secret=''):
            if user.two_factor_secret:
                # Encrypt the secret
                encrypted_bytes = fernet.encrypt(user.two_factor_secret.encode('utf-8'))
                encrypted_string = base64.b64encode(encrypted_bytes).decode('utf-8')
                
                # Update the new field
                user._two_factor_secret = encrypted_string
                user.save(update_fields=['_two_factor_secret'])
                print(f"Encrypted 2FA secret for user: {user.email}")
    
    except Exception as e:
        print(f"Error encrypting 2FA secrets: {e}")
        # Clear secrets if encryption fails
        User.objects.filter(two_factor_enabled=True).update(
            two_factor_secret='',
            two_factor_enabled=False,
            backup_tokens=[]
        )


def reverse_encrypt_2fa_secrets(apps, schema_editor):
    """Reverse migration - decrypt secrets back to plain text"""
    # This is dangerous and should not be done in production
    # We'll just disable 2FA for affected users
    User = apps.get_model('users', 'User')
    User.objects.filter(two_factor_enabled=True).update(
        two_factor_secret='',
        two_factor_enabled=False,
        backup_tokens=[]
    )


class Migration(migrations.Migration):
    
    dependencies = [
        ('users', '0002_alter_user_managers_remove_user_username'),
    ]

    operations = [
        # First add the new encrypted field
        migrations.AddField(
            model_name='user',
            name='_two_factor_secret',
            field=models.CharField(blank=True, max_length=256, help_text='Encrypted 2FA secret'),
        ),
        
        # Migrate existing data
        migrations.RunPython(
            encrypt_existing_2fa_secrets,
            reverse_encrypt_2fa_secrets,
        ),
        
        # Remove the old plain text field
        migrations.RemoveField(
            model_name='user',
            name='two_factor_secret',
        ),
    ]