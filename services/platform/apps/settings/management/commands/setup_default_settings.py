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
                category, _setting_name = key.split(".", 1)

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
            # Company & Branding
            "company.legal_name": "Legal entity name used on invoices and legal documents",
            "company.registration_number": "Company registration number (CUI/J-number)",
            "company.address": "Registered office address for legal documents",
            "company.email_contact": "Primary contact email displayed on the website",
            "company.email_support": "Support email for customer-facing communications",
            "company.email_privacy": "Email address for privacy-related inquiries",
            "company.email_dpo": "Data Protection Officer email for GDPR requests",
            "company.email_noreply": "No-reply sender address for automated emails",
            "company.phone": "Company phone number for customer support",
            # Billing & Invoicing
            "billing.proforma_validity_days": "Number of days a proforma invoice remains valid",
            "billing.payment_grace_period_days": "Grace period in days after invoice due date",
            "billing.invoice_payment_terms_days": "Default number of days until invoice payment is due",
            "billing.vat_rate": "Romanian VAT rate (21%)",
            "billing.max_payment_amount_cents": "Maximum allowed single payment amount in cents",
            "billing.payment_retry_attempts": "Default number of payment retry attempts",
            "billing.payment_retry_delay_hours": "Hours between automatic payment retries",
            "billing.negative_balance_threshold": "Minimum negative balance before alerts trigger",
            "billing.subscription_grace_period_days": "Days after subscription expiry before suspension",
            "billing.max_payment_retry_attempts": "Maximum payment retry attempts before giving up",
            "billing.efactura_minimum_amount_cents": "Minimum invoice amount for e-Factura submission",
            "billing.efactura_submission_deadline_days": "Days after invoice to submit to e-Factura",
            "billing.efactura_deadline_warning_hours": "Hours before deadline to send warning alerts",
            "billing.efactura_batch_size": "Number of invoices per e-Factura batch submission",
            "billing.efactura_api_max_retries": "Maximum API retry attempts for e-Factura calls",
            "billing.efactura_api_timeout_seconds": "Timeout for e-Factura API requests",
            "billing.event_grace_period_hours": "Grace period for billing event deduplication",
            "billing.future_event_drift_minutes": "Allowed clock drift for future event detection",
            "billing.alert_cooldown_hours": "Hours between repeated billing alert notifications",
            "billing.task_retry_delay_seconds": "Delay between billing task retries",
            "billing.task_max_retries": "Maximum retries for billing background tasks",
            # Users & Authentication
            "users.session_timeout_minutes": "User session timeout in minutes",
            "users.mfa_required_for_staff": "Require MFA for all staff accounts",
            "users.max_login_attempts": "Maximum login attempts before account lockout",
            "users.account_lockout_duration_minutes": "Minutes to lock account after max failed attempts",
            "users.admin_session_timeout_minutes": "Admin session timeout in minutes",
            "users.backup_code_count": "Number of 2FA backup codes to generate per user",
            "users.credential_max_age_days": "Maximum age of stored credentials before rotation",
            "users.credential_rotation_retry_limit": "Maximum retries for credential rotation",
            "users.login_rate_limit_per_hour": "Maximum login attempts per IP per hour",
            "users.security_lockout_failure_threshold": "Failed attempts before security lockout",
            # Domain Management
            "domains.registration_enabled": "Enable domain registration functionality",
            "domains.auto_renewal_enabled": "Enable automatic domain renewal",
            "domains.renewal_notice_days": "Days before expiry to send renewal notices",
            "domains.expiry_critical_days": "Days before expiry for critical alerts",
            "domains.expiry_warning_days": "Days before expiry for warning alerts",
            "domains.max_per_package": "Maximum domains allowed per hosting package",
            "domains.max_subdomains_per_domain": "Maximum subdomains per domain",
            "domains.whois_privacy_price_cents": "WHOIS privacy protection annual price in cents",
            # Service Provisioning
            "provisioning.auto_setup_enabled": "Enable automatic service provisioning",
            "provisioning.setup_timeout_minutes": "Timeout for automatic provisioning",
            "provisioning.suspend_timeout_minutes": "Timeout for service suspension operations",
            "provisioning.terminate_timeout_minutes": "Timeout for service termination operations",
            "provisioning.default_disk_quota_gb": "Default disk quota for new packages in GB",
            "provisioning.default_bandwidth_quota_gb": "Default bandwidth quota for new packages in GB",
            "provisioning.max_email_accounts_per_package": "Maximum email accounts per hosting package",
            "provisioning.recovery_excellent_threshold": "Recovery success rate for excellent status (%)",
            "provisioning.recovery_good_threshold": "Recovery success rate for good status (%)",
            "provisioning.recovery_warning_threshold": "Recovery success rate for warning status (%)",
            "provisioning.max_backup_size_gb": "Maximum backup size per account in GB",
            "provisioning.backup_retention_days": "Days to retain provisioning backups",
            "provisioning.high_value_plan_threshold_cents": "Plan price threshold for high-value alerts",
            "provisioning.resource_usage_alert_threshold": "Resource usage percentage to trigger alerts",
            "provisioning.server_overload_threshold": "Server load percentage for overload alerts",
            "provisioning.long_provisioning_threshold_minutes": "Minutes before provisioning is considered slow",
            # Tickets & Support
            "tickets.sla_critical_response_hours": "SLA response time for critical tickets (hours)",
            "tickets.sla_high_response_hours": "SLA response time for high-priority tickets (hours)",
            "tickets.sla_standard_response_hours": "SLA response time for standard tickets (hours)",
            "tickets.sla_low_response_hours": "SLA response time for low-priority tickets (hours)",
            "tickets.auto_escalation_hours": "Hours before unresponsive tickets auto-escalate",
            "tickets.max_reassignments": "Maximum times a ticket can be reassigned",
            "tickets.max_file_size_bytes": "Maximum file upload size for ticket attachments (bytes)",
            "tickets.allowed_file_extensions": "Allowed file extensions for ticket attachments",
            "tickets.max_attachments_per_ticket": "Maximum file attachments per ticket",
            "tickets.security_alert_threshold": "Suspicious events before security alert triggers",
            # Security & Access
            "security.rate_limit_per_hour": "API rate limit per user per hour",
            "security.require_2fa_for_admin": "Require 2FA for administrative access",
            "security.api_burst_limit": "Maximum API requests in a burst window",
            "security.max_customer_lookups_per_hour": "Maximum customer lookups per user per hour",
            "security.suspicious_ip_threshold": "Failed requests from IP before flagging",
            "security.registration_rate_limit_per_ip": "Maximum registrations per IP per hour",
            "security.invitation_rate_limit_per_user": "Maximum invitations per user per hour",
            "security.company_check_rate_limit_per_ip": "Maximum company checks per IP per hour",
            # Monitoring & Alerts
            "monitoring.cpu_warning_threshold": "CPU usage percentage to trigger warnings",
            "monitoring.memory_warning_threshold": "Memory usage percentage to trigger warnings",
            "monitoring.disk_warning_threshold": "Disk usage percentage to trigger warnings",
            "monitoring.alert_cooldown_minutes": "Minutes between repeated monitoring alerts",
            "monitoring.health_check_interval_minutes": "Minutes between health check runs",
            # Notifications
            "notifications.email_enabled": "Enable email notifications",
            "notifications.sms_enabled": "Enable SMS notifications",
            "notifications.max_recipients_per_batch": "Maximum email recipients per batch send",
            "notifications.email_batch_size": "Number of emails to process per batch",
            "notifications.digest_frequency_hours": "Hours between notification digest emails",
            "notifications.max_history": "Maximum notification history entries to retain",
            "notifications.email_max_retries": "Maximum retries for failed email delivery",
            # GDPR & Data Retention
            "gdpr.data_retention_years": "Years to retain customer data before purge",
            "gdpr.log_retention_months": "Months to retain application logs",
            "gdpr.export_retention_days": "Days to retain GDPR data export files",
            "gdpr.audit_log_retention_years": "Years to retain audit log entries",
            "gdpr.failed_login_retention_months": "Months to retain failed login records",
            # External Integrations
            "integrations.webhook_retry_attempts": "Maximum retry attempts for webhook delivery",
            "integrations.webhook_timeout_seconds": "Timeout for webhook HTTP requests",
            "integrations.webhook_batch_size": "Number of webhooks to process per batch",
            "integrations.api_request_timeout_seconds": "Timeout for external API requests",
            "integrations.api_connection_timeout_seconds": "Connection timeout for external APIs",
            # UI & Display
            "ui.default_page_size": "Default number of items per page in lists",
            "ui.max_page_size": "Maximum allowed items per page",
            "ui.min_page_size": "Minimum allowed items per page",
            "ui.max_attachment_size_mb": "Maximum attachment size in megabytes",
            # Promotions & Discounts
            "promotions.max_discount_percent": "Maximum allowed discount percentage",
            "promotions.max_discount_amount_cents": "Maximum allowed discount amount in cents",
            "promotions.max_coupon_batch_size": "Maximum coupons to generate in one batch",
            # System Configuration
            "system.maintenance_mode": "System maintenance mode status",
            "system.backup_retention_days": "Number of days to retain backups",
            # Node Deployment
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
            # Company
            "company.legal_name": "Appears on invoices, contracts, and legal pages.",
            "company.email_contact": "Public-facing contact shown on website footer.",
            "company.email_support": "Used in support-related email templates.",
            "company.email_privacy": "Shown on privacy policy page for GDPR inquiries.",
            "company.email_dpo": "Data Protection Officer contact for GDPR compliance.",
            "company.email_noreply": "Sender address for automated system emails.",
            # Billing
            "billing.vat_rate": "Romanian standard VAT rate. Update only when tax law changes.",
            "billing.max_payment_amount_cents": "Safety limit to prevent erroneous large payments.",
            "billing.payment_retry_delay_hours": "Time between automatic payment collection retries.",
            "billing.negative_balance_threshold": "Decimal value. Alerts trigger when balance falls below this.",
            "billing.subscription_grace_period_days": "Days a customer can use service after payment failure.",
            "billing.efactura_minimum_amount_cents": "Invoices below this amount skip e-Factura submission.",
            "billing.efactura_submission_deadline_days": "Romanian law requires submission within 5 days.",
            "billing.efactura_deadline_warning_hours": "Alert staff this many hours before deadline.",
            "billing.efactura_batch_size": "Larger batches are faster but use more memory.",
            "billing.efactura_api_timeout_seconds": "Increase if ANAF servers are slow.",
            "billing.event_grace_period_hours": "Prevents duplicate billing event processing.",
            "billing.alert_cooldown_hours": "Prevents alert flooding for the same issue.",
            "billing.task_retry_delay_seconds": "Celery task retry backoff delay.",
            # Users
            "users.mfa_required_for_staff": "When enabled, all staff users must set up 2FA.",
            "users.account_lockout_duration_minutes": "Temporary lockout after max failed login attempts.",
            "users.admin_session_timeout_minutes": "Shorter than regular sessions for security.",
            "users.backup_code_count": "One-time codes for 2FA recovery. Standard is 10.",
            "users.credential_max_age_days": "Credentials older than this trigger rotation warnings.",
            "users.login_rate_limit_per_hour": "Per-IP rate limit to prevent brute force attacks.",
            # Domains
            "domains.registration_enabled": "Disable to temporarily stop accepting new domain registrations.",
            "domains.expiry_critical_days": "Triggers urgent renewal notifications.",
            "domains.expiry_warning_days": "Triggers standard renewal reminder emails.",
            "domains.whois_privacy_price_cents": "Annual fee for WHOIS privacy protection service.",
            # Provisioning
            "provisioning.suspend_timeout_minutes": "Service suspension should complete within this time.",
            "provisioning.terminate_timeout_minutes": "Full account removal timeout.",
            "provisioning.recovery_excellent_threshold": "Recovery rate above this = excellent health.",
            "provisioning.recovery_good_threshold": "Recovery rate above this = good health.",
            "provisioning.recovery_warning_threshold": "Recovery rate below this = warning status.",
            "provisioning.high_value_plan_threshold_cents": "Plans above this price get priority support.",
            "provisioning.resource_usage_alert_threshold": "Percentage of quota before alerting customer.",
            "provisioning.server_overload_threshold": "Server load percentage triggering admin alerts.",
            # Tickets
            "tickets.sla_critical_response_hours": "Response SLA for P1/critical tickets.",
            "tickets.sla_high_response_hours": "Response SLA for P2/high-priority tickets.",
            "tickets.max_file_size_bytes": "Maximum upload size in bytes. Default: 2MB (2097152).",
            "tickets.allowed_file_extensions": "JSON list of permitted file extensions.",
            "tickets.security_alert_threshold": "Number of suspicious events before alerting security team.",
            # Security
            "security.require_2fa_for_admin": "Recommended for production environments.",
            "security.api_burst_limit": "Maximum API calls in a short burst window.",
            "security.suspicious_ip_threshold": "Failed requests before IP is flagged for review.",
            # Monitoring
            "monitoring.cpu_warning_threshold": "Percentage. Alerts fire when CPU exceeds this.",
            "monitoring.memory_warning_threshold": "Percentage. Alerts fire when memory exceeds this.",
            "monitoring.disk_warning_threshold": "Percentage. Alerts fire when disk exceeds this.",
            "monitoring.alert_cooldown_minutes": "Prevents alert storms for persistent issues.",
            # Notifications
            "notifications.max_recipients_per_batch": "Split large sends into batches of this size.",
            "notifications.digest_frequency_hours": "How often to send notification digest emails.",
            "notifications.email_max_retries": "Retries before marking email delivery as failed.",
            # GDPR
            "gdpr.data_retention_years": "Romanian fiscal law requires minimum 7 years for invoices.",
            "gdpr.log_retention_months": "Application logs older than this are purged.",
            "gdpr.export_retention_days": "GDPR export files auto-deleted after this period.",
            "gdpr.audit_log_retention_years": "Audit trails kept longer for compliance.",
            "gdpr.failed_login_retention_months": "Security data retention for failed login attempts.",
            # Integrations
            "integrations.webhook_retry_attempts": "Webhooks retry with exponential backoff.",
            "integrations.webhook_timeout_seconds": "HTTP timeout for outgoing webhook requests.",
            "integrations.api_request_timeout_seconds": "Timeout for calls to external APIs.",
            "integrations.api_connection_timeout_seconds": "TCP connection timeout for external APIs.",
            # UI
            "ui.default_page_size": "Used when no page_size parameter is specified.",
            "ui.max_page_size": "Prevents excessively large page requests.",
            # Promotions
            "promotions.max_discount_percent": "Cap on percentage-based discounts.",
            "promotions.max_discount_amount_cents": "Cap on absolute discount amounts.",
            "promotions.max_coupon_batch_size": "Maximum coupons generated in one operation.",
            # System
            "system.maintenance_mode": "When enabled, only staff users can access the system.",
            # Node Deployment
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
