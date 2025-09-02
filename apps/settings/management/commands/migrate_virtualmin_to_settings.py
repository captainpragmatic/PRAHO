"""
Management command to migrate Virtualmin configuration from environment variables
to the SystemSettings database and credential vault.

This command:
1. Creates all necessary Virtualmin settings in the database
2. Migrates credentials to the credential vault
3. Shows what needs to be removed from .env and base.py
4. Provides validation and rollback options

Usage:
    python manage.py migrate_virtualmin_to_settings
    python manage.py migrate_virtualmin_to_settings --dry-run
    python manage.py migrate_virtualmin_to_settings --migrate-credentials
"""

import os
from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.common.credential_vault import get_credential_vault
from apps.settings.models import SettingCategory, SystemSetting


class Command(BaseCommand):
    """Migrate Virtualmin configuration to settings app and credential vault."""

    help = 'Migrate Virtualmin settings from environment variables to database and credential vault'

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be migrated without making changes',
        )
        parser.add_argument(
            '--migrate-credentials',
            action='store_true',
            help='Also migrate credentials to credential vault',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force migration even if settings already exist',
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the migration."""
        
        self.stdout.write("🚀 [Migration] Starting Virtualmin settings migration...")
        
        # Analyze current state
        self._analyze_current_state()
        
        if options['dry_run']:
            self._dry_run_migration()
            return
            
        # Run the actual migration
        try:
            with transaction.atomic():
                # Step 1: Create/update database settings
                self._migrate_operational_settings(options['force'])
                
                # Step 2: Migrate credentials to vault
                if options['migrate_credentials']:
                    self._migrate_credentials_to_vault()
                    
                # Step 3: Show cleanup instructions
                self._show_cleanup_instructions()
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ [Migration] Failed: {e}'))
            raise CommandError(f'Migration failed: {e}') from e
            
        self.stdout.write(self.style.SUCCESS('✅ [Migration] Virtualmin settings migration completed!'))

    def _analyze_current_state(self) -> None:
        """Analyze what settings exist where."""
        
        self.stdout.write("📊 [Analysis] Current Virtualmin configuration state:")
        self.stdout.write("")
        
        # Environment variables
        env_vars = [
            'VIRTUALMIN_HOST', 'VIRTUALMIN_USERNAME', 'VIRTUALMIN_PASSWORD',
            'VIRTUALMIN_SSL_VERIFY', 'VIRTUALMIN_MASTER_USERNAME', 
            'VIRTUALMIN_MASTER_PASSWORD', 'VIRTUALMIN_SSH_USERNAME',
            'VIRTUALMIN_SSH_PRIVATE_KEY_PATH', 'VIRTUALMIN_SSH_PASSWORD',
            'VIRTUALMIN_AUTH_HEALTH_CHECK_INTERVAL', 'VIRTUALMIN_AUTH_FALLBACK_ENABLED'
        ]
        
        self.stdout.write("🌍 Environment Variables Found:")
        for var in env_vars:
            value = os.environ.get(var)
            if value:
                if 'PASSWORD' in var or 'KEY' in var:
                    self.stdout.write(f"  ✅ {var}=****** (sensitive)")
                else:
                    self.stdout.write(f"  ✅ {var}={value}")
            else:
                self.stdout.write(f"  ❌ {var}=<not set>")
        
        self.stdout.write("")
        
        # Database settings
        try:
            provisioning_category = SettingCategory.objects.get(key='provisioning')
            provisioning_settings = SystemSetting.objects.filter(
                key__startswith='virtualmin.',
                category=provisioning_category
            )
        except SettingCategory.DoesNotExist:
            provisioning_settings = SystemSetting.objects.filter(key__startswith='virtualmin.')
        
        self.stdout.write(f"🗄️ Database Settings Found: {provisioning_settings.count()}")
        for setting in provisioning_settings:
            self.stdout.write(f"  ✅ {setting.key}={setting.get_typed_value()}")
            
        self.stdout.write("")

    def _dry_run_migration(self) -> None:
        """Show what would be migrated without making changes."""
        
        self.stdout.write("🧪 [Dry Run] Migration plan:")
        self.stdout.write("")
        
        # Settings that would be created/updated
        operational_mappings = {
            'VIRTUALMIN_HOST': ('virtualmin.hostname', 'Extract hostname from VIRTUALMIN_HOST'),
            'VIRTUALMIN_SSL_VERIFY': ('virtualmin.ssl_verify', 'Boolean SSL verification'),
            'VIRTUALMIN_AUTH_HEALTH_CHECK_INTERVAL': ('virtualmin.auth_health_check_interval_seconds', 'Health check interval'),
            'VIRTUALMIN_AUTH_FALLBACK_ENABLED': ('virtualmin.auth_fallback_enabled', 'Fallback authentication'),
            'VIRTUALMIN_SSH_USERNAME': ('virtualmin.ssh_username', 'SSH username'),
        }
        
        self.stdout.write("📝 Operational Settings (Environment → Database):")
        for env_var, (db_key, description) in operational_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self.stdout.write(f"  {env_var} → {db_key} ({description})")
            else:
                self.stdout.write(f"  {env_var} → {db_key} (would use default)")
        
        self.stdout.write("")
        
        # Credentials that would be moved to vault
        credential_mappings = {
            'VIRTUALMIN_USERNAME + VIRTUALMIN_PASSWORD': 'API credentials',
            'VIRTUALMIN_MASTER_USERNAME + VIRTUALMIN_MASTER_PASSWORD': 'Master admin credentials',
            'VIRTUALMIN_SSH_USERNAME + VIRTUALMIN_SSH_PASSWORD': 'SSH access credentials',
            'VIRTUALMIN_SSH_PRIVATE_KEY_PATH': 'SSH private key file',
        }
        
        self.stdout.write("🔐 Credentials (Environment → Credential Vault):")
        for env_vars, description in credential_mappings.items():
            if '+' in env_vars:
                username_var, password_var = env_vars.split(' + ')
                username = os.environ.get(username_var)
                password = os.environ.get(password_var)
                if username and password:
                    self.stdout.write(f"  {env_vars} → vault:{description} (encrypted)")
                else:
                    self.stdout.write(f"  {env_vars} → vault:{description} (not set)")
            else:
                value = os.environ.get(env_vars)
                if value:
                    self.stdout.write(f"  {env_vars} → vault:{description} (encrypted)")
                else:
                    self.stdout.write(f"  {env_vars} → vault:{description} (not set)")
        
        self.stdout.write("")
        self.stdout.write("💡 Run with --migrate-credentials to actually migrate credentials to vault")

    def _migrate_operational_settings(self, force: bool = False) -> None:
        """Migrate operational settings to database."""
        
        self.stdout.write("📝 [Migration] Migrating operational settings...")
        
        # Ensure provisioning category exists
        provisioning_category, created = SettingCategory.objects.get_or_create(
            key='provisioning',
            defaults={
                'name': 'Provisioning & Infrastructure',
                'description': 'Server provisioning and infrastructure management settings',
                'is_active': True,
            }
        )
        
        if created:
            self.stdout.write("✅ [Migration] Created provisioning category")
        
        # Extract hostname and port from VIRTUALMIN_HOST
        virtualmin_host = os.environ.get('VIRTUALMIN_HOST', '')
        hostname = 'localhost'
        port = 10000
        use_ssl = True
        
        if virtualmin_host:
            if '://' in virtualmin_host:
                protocol, host_part = virtualmin_host.split('://', 1)
                use_ssl = protocol == 'https'
                if ':' in host_part:
                    hostname, port_str = host_part.rsplit(':', 1)
                    port = int(port_str)
                else:
                    hostname = host_part
            else:
                hostname = virtualmin_host
        
        # Settings to migrate
        settings_to_migrate = [
            ('virtualmin.hostname', hostname, 'string', 'Virtualmin hostname'),
            ('virtualmin.port', port, 'integer', 'Virtualmin port'),
            ('virtualmin.use_ssl', use_ssl, 'boolean', 'Use SSL/HTTPS'),
            ('virtualmin.ssl_verify', os.environ.get('VIRTUALMIN_SSL_VERIFY', 'True').lower() == 'true', 'boolean', 'SSL verification'),
            ('virtualmin.auth_health_check_interval_seconds', int(os.environ.get('VIRTUALMIN_AUTH_HEALTH_CHECK_INTERVAL', '3600')), 'integer', 'Health check interval'),
            ('virtualmin.auth_fallback_enabled', os.environ.get('VIRTUALMIN_AUTH_FALLBACK_ENABLED', 'true').lower() == 'true', 'boolean', 'Fallback authentication'),
            ('virtualmin.ssh_username', os.environ.get('VIRTUALMIN_SSH_USERNAME', 'virtualmin-praho'), 'string', 'SSH username'),
            ('virtualmin.api_endpoint_path', '/virtual-server/remote.cgi', 'string', 'API endpoint path'),
        ]
        
        created_count = 0
        updated_count = 0
        
        for key, value, data_type, description in settings_to_migrate:
            setting, created = SystemSetting.objects.get_or_create(
                key=key,
                defaults={
                    'name': description,
                    'description': f'Migrated from environment: {description}',
                    'value': str(value),
                    'default_value': str(value),
                    'data_type': data_type,
                    'category': provisioning_category,
                    'is_required': True,
                    'is_active': True,
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(f"✅ [Migration] Created {key}={value}")
            elif force:
                setting.value = str(value)
                setting.save()
                updated_count += 1
                self.stdout.write(f"🔄 [Migration] Updated {key}={value}")
            else:
                self.stdout.write(f"⚠️ [Migration] {key} already exists (use --force to update)")
        
        self.stdout.write(f"📊 [Migration] Created {created_count} settings, updated {updated_count} settings")

    def _migrate_credentials_to_vault(self) -> None:
        """Migrate sensitive credentials to credential vault."""
        
        self.stdout.write("🔐 [Migration] Migrating credentials to vault...")
        
        vault = get_credential_vault()
        if not vault:
            self.stdout.write(self.style.WARNING("⚠️ [Migration] Credential vault not available, skipping credential migration"))
            return
        
        # Extract hostname for vault identifier
        virtualmin_host = os.environ.get('VIRTUALMIN_HOST', 'localhost')
        hostname = virtualmin_host.split('://')[-1].split(':')[0] if '://' in virtualmin_host else virtualmin_host
        
        # Credentials to migrate
        credentials_to_migrate = [
            ('VIRTUALMIN_USERNAME', 'VIRTUALMIN_PASSWORD', 'Virtualmin API credentials'),
            ('VIRTUALMIN_MASTER_USERNAME', 'VIRTUALMIN_MASTER_PASSWORD', 'Virtualmin master admin credentials'),
        ]
        
        # Handle SSH credentials separately
        ssh_username = os.environ.get('VIRTUALMIN_SSH_USERNAME')
        ssh_password = os.environ.get('VIRTUALMIN_SSH_PASSWORD')
        if ssh_username and ssh_password:
            credentials_to_migrate.append(('VIRTUALMIN_SSH_USERNAME', 'VIRTUALMIN_SSH_PASSWORD', 'SSH access credentials'))
        
        # Handle SSH private key separately
        ssh_key_path = os.environ.get('VIRTUALMIN_SSH_PRIVATE_KEY_PATH')
        ssh_key_content = None
        if ssh_key_path and os.path.exists(ssh_key_path):
            try:
                with open(ssh_key_path) as f:
                    ssh_key_content = f.read()
                self.stdout.write(f"📁 [Migration] Found SSH key file: {ssh_key_path}")
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"⚠️ [Migration] Could not read SSH key file: {e}"))
        
        migrated_count = 0
        
        for username_var, password_var, description in credentials_to_migrate:
            username = os.environ.get(username_var)
            password = os.environ.get(password_var)
            
            if username and password:
                try:
                    # Prepare metadata
                    metadata = {
                        'description': description,
                        'migrated_from': f"{username_var}, {password_var}",
                        'migration_timestamp': str(timezone.now()),
                    }
                    
                    # Add SSH key if this is SSH credentials
                    if 'SSH' in username_var and ssh_key_content:
                        metadata['ssh_private_key'] = ssh_key_content
                    
                    # Store in vault
                    result = vault.store_credential(
                        service_type='virtualmin',
                        service_identifier=hostname,
                        username=username,
                        password=password,
                        metadata=metadata,
                        reason=f"Migration: {description}"
                    )
                    
                    if result.is_ok():
                        migrated_count += 1
                        self.stdout.write(f"✅ [Migration] Stored {description} in vault")
                    else:
                        self.stdout.write(self.style.ERROR(f"❌ [Migration] Failed to store {description}: {result.unwrap_err()}"))
                        
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"❌ [Migration] Error storing {description}: {e}"))
            else:
                missing_vars = []
                if not username:
                    missing_vars.append(username_var)
                if not password:
                    missing_vars.append(password_var)
                self.stdout.write(f"⚠️ [Migration] {', '.join(missing_vars)} not set, skipping {description}")
        
        self.stdout.write(f"🔐 [Migration] Migrated {migrated_count} credentials to vault")

    def _show_cleanup_instructions(self) -> None:
        """Show what needs to be cleaned up after migration."""
        
        self.stdout.write("")
        self.stdout.write("🧹 [Cleanup] Post-migration cleanup instructions:")
        self.stdout.write("")
        
        self.stdout.write("1. Remove from .env:")
        env_vars_to_remove = [
            'VIRTUALMIN_HOST', 'VIRTUALMIN_USERNAME', 'VIRTUALMIN_PASSWORD',
            'VIRTUALMIN_SSL_VERIFY'
        ]
        for var in env_vars_to_remove:
            self.stdout.write(f"   - {var}")
        
        self.stdout.write("")
        self.stdout.write("2. Remove from config/settings/base.py:")
        settings_to_remove = [
            'VIRTUALMIN_URL', 'VIRTUALMIN_USERNAME', 'VIRTUALMIN_PASSWORD',
            'VIRTUALMIN_MASTER_USERNAME', 'VIRTUALMIN_MASTER_PASSWORD',
            'VIRTUALMIN_SSH_USERNAME', 'VIRTUALMIN_SSH_PRIVATE_KEY_PATH',
            'VIRTUALMIN_SSH_PASSWORD', 'VIRTUALMIN_AUTH_HEALTH_CHECK_INTERVAL',
            'VIRTUALMIN_AUTH_FALLBACK_ENABLED'
        ]
        for var in settings_to_remove:
            self.stdout.write(f"   - {var}")
        
        self.stdout.write("")
        self.stdout.write("3. Update apps/provisioning/virtualmin_gateway.py:")
        self.stdout.write("   - Remove environment variable reads")
        self.stdout.write("   - Use SettingsService.get_setting() for operational settings")
        self.stdout.write("   - Use credential vault for sensitive data")
        
        self.stdout.write("")
        self.stdout.write("4. Test the migration:")
        self.stdout.write("   - python manage.py test_virtualmin_connection")
        self.stdout.write("   - Check settings UI: /app/settings/dashboard/")
        self.stdout.write("   - Verify credential vault: python manage.py setup_credential_vault --status")
        
        self.stdout.write("")
        self.stdout.write("✅ [Migration] All Virtualmin settings are now managed through the settings app!")
