"""
Management command to set up required Virtualmin settings in SystemSettings.

This creates the necessary database configuration entries for Virtualmin
integration, following the hybrid approach where operational settings
are stored in the database and security credentials in environ        self.stdout.write('The following environment variables are required for Virtualmin authentication:')
        self.stdout.write('  - VIRTUALMIN_ADMIN_USER=your_admin_username')
        self.stdout.write('  - VIRTUALMIN_ADMIN_PASSWORD=your_admin_password')
        self.stdout.write('')
        self.stdout.write('Optional performance tuning:')
        self.stdout.write('  - VIRTUALMIN_PINNED_CERT_SHA256=sha256_hash_for_cert_pinning')
        self.stdout.write('')
        self.stdout.write('For credential vault (recommended):')
        self.stdout.write('  1. Set up credential vault: python manage.py setup_credential_vault')
        self.stdout.write('  2. Migrate credentials: python manage.py setup_credential_vault --migrate-env-vars')
        self.stdout.write('  3. Enable vault in settings: CREDENTIAL_VAULT_ENABLED=true')
        self.stdout.write('')
        self.stdout.write('Next steps:')
        self.stdout.write('  1. Configure your Virtualmin settings in the admin panel')
        self.stdout.write('  2. Test connection: python manage.py test_virtualmin_connection')
        self.stdout.write('  3. Run health check: python manage.py virtualmin_health_check')ables.

Usage:
    python manage.py setup_virtualmin_settings
"""

from typing import Any

from django.core.management.base import BaseCommand

from apps.settings.models import SettingCategory, SystemSetting


class Command(BaseCommand):
    """Set up Virtualmin configuration settings in the database."""

    help = "Create required Virtualmin settings in SystemSettings database"

    def handle(self, *args: Any, **options: Any) -> None:
        """Create the required Virtualmin settings."""

        # =====================================================================================
        # STEP 1: GET OR CREATE PROVISIONING CATEGORY 🔧
        # =====================================================================================

        provisioning_category, created = SettingCategory.objects.get_or_create(
            key="provisioning",
            defaults={
                "name": "Provisioning",
                "description": "Settings for server provisioning and hosting automation",
                "is_active": True,
                "display_order": 40,
            },
        )

        if created:
            self.stdout.write(self.style.SUCCESS("✅ [Setup] Created provisioning category"))
        else:
            self.stdout.write(self.style.WARNING("⚠️ [Setup] Provisioning category already exists"))

        # =====================================================================================
        # STEP 2: CREATE VIRTUALMIN OPERATIONAL SETTINGS 🌐
        # =====================================================================================

        virtualmin_settings = [
            # Core Connection Settings
            {
                "key": "virtualmin.hostname",
                "name": "Virtualmin Hostname",
                "description": "Hostname or IP address of the Virtualmin server",
                "value": "localhost",
                "default_value": "localhost",
                "data_type": "string",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.port",
                "name": "Virtualmin Port",
                "description": "Port number for Virtualmin API (usually 10000)",
                "value": 10000,
                "default_value": 10000,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.ssl_verify",
                "name": "SSL Certificate Verification",
                "description": "Verify SSL certificates when connecting to Virtualmin",
                "value": True,
                "default_value": True,
                "data_type": "boolean",
                "category": "provisioning",
                "is_required": True,
            },
            # API Performance Settings
            {
                "key": "virtualmin.request_timeout_seconds",
                "name": "Request Timeout",
                "description": "Timeout for Virtualmin API requests in seconds",
                "value": 30,
                "default_value": 30,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.max_retries",
                "name": "Maximum Retries",
                "description": "Maximum number of retry attempts for failed requests",
                "value": 3,
                "default_value": 3,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.rate_limit_qps",
                "name": "Rate Limit QPS",
                "description": "Maximum queries per second to Virtualmin API",
                "value": 10,
                "default_value": 10,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.connection_pool_size",
                "name": "Connection Pool Size",
                "description": "Maximum number of concurrent connections to Virtualmin",
                "value": 10,
                "default_value": 10,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.rate_limit_max_calls_per_hour",
                "name": "Rate Limit Max Calls Per Hour",
                "description": "Maximum API calls per hour per server",
                "value": 100,
                "default_value": 100,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            # Authentication & Security
            {
                "key": "virtualmin.auth_health_check_interval_seconds",
                "name": "Auth Health Check Interval",
                "description": "Interval for authentication health checks in seconds",
                "value": 3600,
                "default_value": 3600,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.auth_fallback_enabled",
                "name": "Auth Fallback Enabled",
                "description": "Enable fallback authentication methods",
                "value": True,
                "default_value": True,
                "data_type": "boolean",
                "category": "provisioning",
                "is_required": True,
            },
            # Backup Settings
            {
                "key": "virtualmin.backup_retention_days",
                "name": "Backup Retention Days",
                "description": "Number of days to retain backups",
                "value": 7,
                "default_value": 7,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.backup_compression_enabled",
                "name": "Backup Compression",
                "description": "Enable compression for backups",
                "value": True,
                "default_value": True,
                "data_type": "boolean",
                "category": "provisioning",
                "is_required": True,
            },
            # Domain Configuration
            {
                "key": "virtualmin.domain_quota_default_mb",
                "name": "Default Domain Quota (MB)",
                "description": "Default disk quota for domains in megabytes",
                "value": 1000,
                "default_value": 1000,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.bandwidth_quota_default_mb",
                "name": "Default Bandwidth Quota (MB)",
                "description": "Default bandwidth quota for domains in megabytes",
                "value": 10000,
                "default_value": 10000,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            # Database Settings
            {
                "key": "virtualmin.mysql_enabled",
                "name": "MySQL Support",
                "description": "Enable MySQL database support",
                "value": True,
                "default_value": True,
                "data_type": "boolean",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.postgresql_enabled",
                "name": "PostgreSQL Support",
                "description": "Enable PostgreSQL database support",
                "value": False,
                "default_value": False,
                "data_type": "boolean",
                "category": "provisioning",
                "is_required": True,
            },
            # PHP Configuration
            {
                "key": "virtualmin.php_version_default",
                "name": "Default PHP Version",
                "description": "Default PHP version for new domains",
                "value": "8.1",
                "default_value": "8.1",
                "data_type": "string",
                "category": "provisioning",
                "is_required": True,
            },
            # SSL & Monitoring
            {
                "key": "virtualmin.ssl_auto_renewal_enabled",
                "name": "SSL Auto-Renewal",
                "description": "Enable automatic SSL certificate renewal",
                "value": True,
                "default_value": True,
                "data_type": "boolean",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.monitoring_enabled",
                "name": "Monitoring Enabled",
                "description": "Enable server and domain monitoring",
                "value": True,
                "default_value": True,
                "data_type": "boolean",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.log_retention_days",
                "name": "Log Retention Days",
                "description": "Number of days to retain server logs",
                "value": 30,
                "default_value": 30,
                "data_type": "integer",
                "category": "provisioning",
                "is_required": True,
            },
            # SSH & Advanced Authentication
            {
                "key": "virtualmin.ssh_username",
                "name": "SSH Username",
                "description": "SSH username for Virtualmin server access",
                "value": "virtualmin-praho",
                "default_value": "virtualmin-praho",
                "data_type": "string",
                "category": "provisioning",
                "is_required": True,
                "is_sensitive": False,
            },
            {
                "key": "virtualmin.ssh_private_key_path",
                "name": "SSH Private Key Path",
                "description": "Path to SSH private key file for server access",
                "value": "/path/to/private/key",
                "default_value": "/path/to/private/key",
                "data_type": "string",
                "category": "provisioning",
                "is_required": False,
                "is_sensitive": True,
            },
            {
                "key": "virtualmin.api_endpoint_path",
                "name": "API Endpoint Path",
                "description": "API endpoint path (usually /virtual-server/remote.cgi)",
                "value": "/virtual-server/remote.cgi",
                "default_value": "/virtual-server/remote.cgi",
                "data_type": "string",
                "category": "provisioning",
                "is_required": True,
            },
            {
                "key": "virtualmin.use_ssl",
                "name": "Use SSL/HTTPS",
                "description": "Use HTTPS for API connections",
                "value": True,
                "default_value": True,
                "data_type": "boolean",
                "category": "provisioning",
                "is_required": True,
            },
        ]

        created_count = 0
        for setting_data in virtualmin_settings:
            setting, created = SystemSetting.objects.get_or_create(key=setting_data["key"], defaults=setting_data)

            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f"✅ [Setup] Created {setting_data['key']}"))
            else:
                self.stdout.write(self.style.WARNING(f"⚠️ [Setup] {setting_data['key']} already exists"))

        # =====================================================================================
        # STEP 3: SUMMARY AND ENVIRONMENT REMINDER 📋
        # =====================================================================================

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(f"🎉 Setup complete! Created {created_count} new settings"))
        self.stdout.write("")
        self.stdout.write(self.style.WARNING("🔒 Security reminder:"))
        self.stdout.write("The following environment variables are required for Virtualmin authentication:")
        self.stdout.write("  - VIRTUALMIN_ADMIN_USER=your_admin_username")
        self.stdout.write("  - VIRTUALMIN_ADMIN_PASSWORD=your_admin_password")
        self.stdout.write("")
        self.stdout.write("Optional performance tuning environment variables:")
        self.stdout.write("  - VIRTUALMIN_REQUEST_TIMEOUT=60")
        self.stdout.write("  - VIRTUALMIN_MAX_RETRIES=3")
        self.stdout.write("  - VIRTUALMIN_RATE_QPS=10")
        self.stdout.write("  - VIRTUALMIN_PINNED_CERT_SHA256=sha256_hash_for_certificate_pinning")
