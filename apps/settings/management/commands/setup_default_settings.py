"""
Django management command to set up default system settings
Creates all default settings defined in SettingsService.DEFAULT_SETTINGS
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


class Command(BaseCommand):
    """⚙️ Set up default system settings for PRAHO Platform"""
    
    help = 'Set up default system settings for PRAHO Platform'

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command line arguments"""
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force update existing settings to default values',
        )
        parser.add_argument(
            '--category',
            type=str,
            help='Only set up settings for specific category',
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the command"""
        force = options.get('force', False)
        category_filter = options.get('category')
        
        self.stdout.write(
            self.style.SUCCESS('🚀 Setting up default system settings...')
        )
        
        created_count = 0
        updated_count = 0
        skipped_count = 0
        
        for key, default_value in SettingsService.DEFAULT_SETTINGS.items():
            # Apply category filter if specified
            if category_filter and not key.startswith(f'{category_filter}.'):
                continue
            
            try:
                # Parse key for category and setting name
                category, setting_name = key.split('.', 1)
                
                # Check if setting exists
                setting, created = SystemSetting.objects.get_or_create(
                    key=key,
                    defaults={
                        'name': self._generate_name_from_key(key),
                        'description': self._generate_description_from_key(key),
                        'category': category,
                        'data_type': self._infer_data_type(default_value),
                        'value': default_value,
                        'default_value': default_value,
                        'is_required': self._is_required_setting(key),
                        'is_sensitive': self._is_sensitive_setting(key),
                        'help_text': self._get_help_text(key),
                    }
                )
                
                if created:
                    created_count += 1
                    self.stdout.write(
                        f"  ✅ Created setting: {key} = {self._safe_display_value(default_value, self._is_sensitive_setting(key))}"
                    )
                elif force:
                    # Update existing setting to default
                    setting.value = default_value
                    setting.default_value = default_value
                    setting.save(update_fields=['value', 'default_value', 'updated_at'])
                    updated_count += 1
                    self.stdout.write(
                        f"  🔄 Updated setting: {key} = {self._safe_display_value(default_value, setting.is_sensitive)}"
                    )
                else:
                    skipped_count += 1
                    self.stdout.write(
                        f"  ⏭️  Skipped existing: {key} (use --force to update)"
                    )
                    
            except ValueError as e:
                self.stdout.write(
                    self.style.ERROR(f"  ❌ Error with setting {key}: {e}")
                )
                continue
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"  🔥 Unexpected error with setting {key}: {e}")
                )
                continue
        
        # Summary
        self.stdout.write(self.style.SUCCESS('\n📊 Setup Summary:'))
        self.stdout.write(f"  • Created: {created_count} settings")
        self.stdout.write(f"  • Updated: {updated_count} settings")
        self.stdout.write(f"  • Skipped: {skipped_count} settings")
        
        if category_filter:
            self.stdout.write(f"  • Category filter: {category_filter}")
        
        self.stdout.write(
            self.style.SUCCESS('✅ Default system settings setup completed!')
        )

    def _generate_name_from_key(self, key: str) -> str:
        """Generate human-readable name from setting key"""
        return key.replace('_', ' ').replace('.', ' - ').title()

    def _generate_description_from_key(self, key: str) -> str:
        """Generate description from setting key"""
        descriptions = {
            'billing.proforma_validity_days': 'Number of days a proforma invoice remains valid',
            'billing.payment_grace_period_days': 'Grace period in days after invoice due date',
            'billing.invoice_due_days': 'Default number of days until invoice is due',
            'billing.vat_rate': 'Romanian VAT rate (19%)',
            'users.session_timeout_minutes': 'User session timeout in minutes',
            'users.mfa_required_for_staff': 'Require MFA for all staff accounts',
            'users.password_reset_timeout_hours': 'Password reset link validity in hours',
            'users.max_login_attempts': 'Maximum login attempts before account lockout',
            'domains.registration_enabled': 'Enable domain registration functionality',
            'domains.auto_renewal_enabled': 'Enable automatic domain renewal',
            'domains.renewal_notice_days': 'Days before expiry to send renewal notices',
            'provisioning.auto_setup_enabled': 'Enable automatic service provisioning',
            'provisioning.setup_timeout_minutes': 'Timeout for automatic provisioning',
            'security.rate_limit_per_hour': 'API rate limit per user per hour',
            'security.require_2fa_for_admin': 'Require 2FA for administrative access',
            'notifications.email_enabled': 'Enable email notifications',
            'notifications.sms_enabled': 'Enable SMS notifications',
            'system.maintenance_mode': 'System maintenance mode status',
            'system.backup_retention_days': 'Number of days to retain backups',
        }
        
        return descriptions.get(key, f'System setting: {self._generate_name_from_key(key)}')

    def _infer_data_type(self, value: Any) -> str:
        """Infer data type from value"""
        if isinstance(value, bool):
            return 'boolean'
        elif isinstance(value, int):
            return 'integer'
        elif isinstance(value, float | str) and str(value).replace('.', '').replace('-', '').isdigit():
            return 'decimal'
        elif isinstance(value, list):
            return 'list'
        elif isinstance(value, dict):
            return 'json'
        else:
            return 'string'

    def _is_required_setting(self, key: str) -> bool:
        """Check if setting is required"""
        required_settings = {
            'billing.vat_rate',
            'users.session_timeout_minutes',
            'security.rate_limit_per_hour',
        }
        return key in required_settings

    def _is_sensitive_setting(self, key: str) -> bool:
        """Check if setting contains sensitive data"""
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential']
        return any(pattern in key.lower() for pattern in sensitive_patterns)

    def _get_help_text(self, key: str) -> str:
        """Get help text for setting"""
        help_texts = {
            'billing.vat_rate': 'Romanian standard VAT rate. Update only when tax law changes.',
            'users.mfa_required_for_staff': 'When enabled, all staff users must set up 2FA.',
            'system.maintenance_mode': 'When enabled, only staff users can access the system.',
            'domains.registration_enabled': 'Disable to temporarily stop accepting new domain registrations.',
            'security.require_2fa_for_admin': 'Recommended for production environments.',
        }
        return help_texts.get(key, '')

    def _safe_display_value(self, value: Any, is_sensitive: bool) -> str:
        """Safely display value, hiding sensitive data"""
        if is_sensitive:
            return '(hidden)'
        return str(value)
