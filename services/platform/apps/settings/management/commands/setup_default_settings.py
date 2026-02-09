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

    help = "Set up default system settings for PRAHO Platform"

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command line arguments"""
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force update existing settings to default values",
        )
        parser.add_argument(
            "--category",
            type=str,
            help="Only set up settings for specific category",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the command"""
        force = options.get("force", False)
        category_filter = options.get("category")

        self.stdout.write(self.style.SUCCESS("🚀 Setting up default system settings..."))

        created_count = 0
        updated_count = 0
        skipped_count = 0

        for key, default_value in SettingsService.DEFAULT_SETTINGS.items():
            # Apply category filter if specified
            if category_filter and not key.startswith(f"{category_filter}."):
                continue

            try:
                # Parse key for category and setting name
                category, setting_name = key.split(".", 1)

                # Check if setting exists
                setting, created = SystemSetting.objects.get_or_create(
                    key=key,
                    defaults={
                        "name": self._generate_name_from_key(key),
                        "description": self._generate_description_from_key(key),
                        "category": category,
                        "data_type": self._infer_data_type(default_value),
                        "value": default_value,
                        "default_value": default_value,
                        "is_required": self._is_required_setting(key),
                        "is_sensitive": self._is_sensitive_setting(key),
                        "help_text": self._get_help_text(key),
                    },
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
                    setting.save(update_fields=["value", "default_value", "updated_at"])
                    updated_count += 1
                    self.stdout.write(
                        f"  🔄 Updated setting: {key} = {self._safe_display_value(default_value, setting.is_sensitive)}"
                    )
                else:
                    skipped_count += 1
                    self.stdout.write(f"  ⏭️  Skipped existing: {key} (use --force to update)")

            except ValueError as e:
                self.stdout.write(self.style.ERROR(f"  ❌ Error with setting {key}: {e}"))
                continue
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  🔥 Unexpected error with setting {key}: {e}"))
                continue

        # Summary
        self.stdout.write(self.style.SUCCESS("\n📊 Setup Summary:"))
        self.stdout.write(f"  • Created: {created_count} settings")
        self.stdout.write(f"  • Updated: {updated_count} settings")
        self.stdout.write(f"  • Skipped: {skipped_count} settings")

        if category_filter:
            self.stdout.write(f"  • Category filter: {category_filter}")

        self.stdout.write(self.style.SUCCESS("✅ Default system settings setup completed!"))

    def _generate_name_from_key(self, key: str) -> str:
        """Generate human-readable name from setting key"""
        return key.replace("_", " ").replace(".", " - ").title()

    def _generate_description_from_key(self, key: str) -> str:
        """Generate description from setting key"""
        descriptions = {
            "billing.proforma_validity_days": "Number of days a proforma invoice remains valid",
            "billing.payment_grace_period_days": "Grace period in days after invoice due date",
            "billing.invoice_due_days": "Default number of days until invoice is due",
            "billing.vat_rate": "Romanian VAT rate (19%)",
            "users.session_timeout_minutes": "User session timeout in minutes",
            "users.mfa_required_for_staff": "Require MFA for all staff accounts",
            "users.password_reset_timeout_hours": "Password reset link validity in hours",
            "users.max_login_attempts": "Maximum login attempts before account lockout",
            "domains.registration_enabled": "Enable domain registration functionality",
            "domains.auto_renewal_enabled": "Enable automatic domain renewal",
            "domains.renewal_notice_days": "Days before expiry to send renewal notices",
            "provisioning.auto_setup_enabled": "Enable automatic service provisioning",
            "provisioning.setup_timeout_minutes": "Timeout for automatic provisioning",
            "security.rate_limit_per_hour": "API rate limit per user per hour",
            "security.require_2fa_for_admin": "Require 2FA for administrative access",
            "notifications.email_enabled": "Enable email notifications",
            "notifications.sms_enabled": "Enable SMS notifications",
            "system.maintenance_mode": "System maintenance mode status",
            "system.backup_retention_days": "Number of days to retain backups",
            # Node Deployment settings
            "node_deployment.terraform_state_backend": "Terraform state backend type (local or s3)",
            "node_deployment.terraform_s3_bucket": "S3 bucket for Terraform state (when using S3 backend)",
            "node_deployment.terraform_s3_region": "AWS region for Terraform S3 state bucket",
            "node_deployment.terraform_s3_key_prefix": "S3 key prefix for Terraform state files",
            "node_deployment.dns_default_zone": "Default DNS zone for node hostnames (e.g., infra.example.com)",
            "node_deployment.dns_cloudflare_zone_id": "Cloudflare zone ID for DNS record creation",
            "node_deployment.dns_cloudflare_api_token": "Cloudflare API token for DNS management",
            "node_deployment.default_provider": "Default cloud provider for new deployments",
            "node_deployment.default_region": "Default region for new deployments",
            "node_deployment.default_environment": "Default environment for new deployments",
            "node_deployment.backup_enabled": "Enable automatic backups on new nodes",
            "node_deployment.backup_storage": "Backup storage type (local or s3)",
            "node_deployment.backup_s3_bucket": "S3 bucket for backups (when using S3 storage)",
            "node_deployment.backup_retention_days": "Number of days to retain local backups",
            "node_deployment.backup_schedule": "Cron schedule for backup jobs",
            "node_deployment.timeout_terraform_apply": "Terraform apply timeout in seconds",
            "node_deployment.timeout_ansible_playbook": "Ansible playbook execution timeout in seconds",
            "node_deployment.timeout_validation": "Node validation timeout in seconds",
            "node_deployment.enabled": "Master enable/disable for node deployment feature",
            "node_deployment.auto_registration": "Automatically register deployed nodes as VirtualminServer",
            "node_deployment.cost_tracking_enabled": "Track costs for deployed nodes",
        }

        return descriptions.get(key, f"System setting: {self._generate_name_from_key(key)}")

    def _infer_data_type(self, value: Any) -> str:
        """Infer data type from value"""
        if isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "integer"
        elif isinstance(value, float | str) and str(value).replace(".", "").replace("-", "").isdigit():
            return "decimal"
        elif isinstance(value, list):
            return "list"
        elif isinstance(value, dict):
            return "json"
        else:
            return "string"

    def _is_required_setting(self, key: str) -> bool:
        """Check if setting is required"""
        required_settings = {
            "billing.vat_rate",
            "users.session_timeout_minutes",
            "security.rate_limit_per_hour",
        }
        return key in required_settings

    def _is_sensitive_setting(self, key: str) -> bool:
        """Check if setting contains sensitive data"""
        sensitive_patterns = ["password", "secret", "key", "token", "credential"]
        return any(pattern in key.lower() for pattern in sensitive_patterns)

    def _get_help_text(self, key: str) -> str:
        """Get help text for setting"""
        help_texts = {
            "billing.vat_rate": "Romanian standard VAT rate. Update only when tax law changes.",
            "users.mfa_required_for_staff": "When enabled, all staff users must set up 2FA.",
            "system.maintenance_mode": "When enabled, only staff users can access the system.",
            "domains.registration_enabled": "Disable to temporarily stop accepting new domain registrations.",
            "security.require_2fa_for_admin": "Recommended for production environments.",
            # Node Deployment help texts
            "node_deployment.terraform_state_backend": "Use 'local' for development, 's3' for production with shared state.",
            "node_deployment.terraform_s3_bucket": "Required when using S3 backend. Must be pre-created.",
            "node_deployment.terraform_s3_region": "e.g., eu-west-1. Required when using S3 backend.",
            "node_deployment.terraform_s3_key_prefix": "Path prefix for organizing state files in S3.",
            "node_deployment.dns_default_zone": "Nodes will be created as {hostname}.{zone}. Use infra.example.com pattern.",
            "node_deployment.dns_cloudflare_zone_id": "Find in Cloudflare dashboard under zone overview.",
            "node_deployment.dns_cloudflare_api_token": "API token with Zone:DNS:Edit permissions.",
            "node_deployment.default_provider": "Currently supported: hetzner. Future: digitalocean, vultr, aws.",
            "node_deployment.default_region": "Region code like fsn1 (Hetzner Falkenstein), nyc1, etc.",
            "node_deployment.default_environment": "Use prd for production, stg for staging, dev for development.",
            "node_deployment.backup_enabled": "Recommended. Configures daily Virtualmin backups on new nodes.",
            "node_deployment.backup_storage": "Local: disk on node. S3: external (requires S3 bucket, TODO).",
            "node_deployment.backup_retention_days": "Older backups are automatically deleted.",
            "node_deployment.backup_schedule": "Cron format. Default: 0 2 * * * (daily at 2 AM).",
            "node_deployment.timeout_terraform_apply": "Increase for slow networks. Default 10 minutes.",
            "node_deployment.timeout_ansible_playbook": "Virtualmin install can take up to 30 minutes.",
            "node_deployment.timeout_validation": "Time for health checks after installation.",
            "node_deployment.enabled": "Disable to prevent any new node deployments.",
            "node_deployment.auto_registration": "When enabled, completed nodes are auto-added to VirtualminServer.",
            "node_deployment.cost_tracking_enabled": "Records hourly costs for cost analysis and billing.",
        }
        return help_texts.get(key, "")

    def _safe_display_value(self, value: Any, is_sensitive: bool) -> str:
        """Safely display value, hiding sensitive data"""
        if is_sensitive:
            return "(hidden)"
        return str(value)
