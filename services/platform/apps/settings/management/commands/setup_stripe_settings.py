"""
Django management command to set up Stripe payment integration settings
Creates encrypted settings for Stripe API keys and configuration
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from apps.settings.models import SettingCategory, SystemSetting


class Command(BaseCommand):
    """💳 Set up Stripe payment integration settings for PRAHO Platform"""

    help = "Set up Stripe payment integration settings with encryption"

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command line arguments"""
        parser.add_argument(
            "--secret-key",
            type=str,
            help="Stripe secret key (will be encrypted)",
        )
        parser.add_argument(
            "--publishable-key",
            type=str,
            help="Stripe publishable key",
        )
        parser.add_argument(
            "--webhook-secret",
            type=str,
            help="Stripe webhook secret (will be encrypted)",
        )
        parser.add_argument(
            "--enabled",
            action="store_true",
            help="Enable Stripe integration",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force update existing settings",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the command"""
        force = options.get("force", False)
        secret_key = options.get("secret_key")
        publishable_key = options.get("publishable_key")
        webhook_secret = options.get("webhook_secret")
        enabled = options.get("enabled", False)

        self.stdout.write(self.style.SUCCESS("💳 Setting up Stripe payment integration settings..."))

        # Ensure integrations category exists
        integrations_category, created = SettingCategory.objects.get_or_create(
            key="integrations",
            defaults={
                "name": "Integrations",
                "description": "Third-party service integration settings",
                "display_order": 8,
                "is_active": True,
            },
        )

        if created:
            self.stdout.write("✅ Created integrations category")

        # Define Stripe settings with metadata
        stripe_settings = [
            {
                "key": "integrations.stripe_secret_key",
                "name": "Stripe Secret Key",
                "description": "Stripe secret API key for server-side operations (encrypted)",
                "data_type": "string",
                "is_sensitive": True,  # This will be encrypted
                "is_required": True,
                "value": secret_key or "",
                "help_text": "Secret key from Stripe Dashboard (starts with sk_)",
            },
            {
                "key": "integrations.stripe_publishable_key",
                "name": "Stripe Publishable Key",
                "description": "Stripe publishable key for client-side integration",
                "data_type": "string",
                "is_sensitive": False,  # Public key, not encrypted
                "is_required": True,
                "value": publishable_key or "",
                "help_text": "Publishable key from Stripe Dashboard (starts with pk_)",
            },
            {
                "key": "integrations.stripe_webhook_secret",
                "name": "Stripe Webhook Secret",
                "description": "Stripe webhook endpoint secret for signature verification (encrypted)",
                "data_type": "string",
                "is_sensitive": True,  # This will be encrypted
                "is_required": True,
                "value": webhook_secret or "",
                "help_text": "Webhook secret from Stripe Dashboard (starts with whsec_)",
            },
            {
                "key": "integrations.stripe_enabled",
                "name": "Stripe Integration Enabled",
                "description": "Enable/disable Stripe payment processing",
                "data_type": "boolean",
                "is_sensitive": False,
                "is_required": True,
                "value": enabled,
                "help_text": "Toggle Stripe payment integration on/off",
            },
        ]

        created_count = 0
        updated_count = 0
        skipped_count = 0

        for setting_data in stripe_settings:
            key = setting_data["key"]

            try:
                # Check if setting already exists
                setting, created = SystemSetting.objects.get_or_create(
                    key=key,
                    defaults={
                        "category": "integrations",
                        "name": setting_data["name"],
                        "description": setting_data["description"],
                        "data_type": setting_data["data_type"],
                        "is_sensitive": setting_data["is_sensitive"],
                        "is_required": setting_data["is_required"],
                        "value": str(setting_data["value"]) if setting_data["value"] is not None else "",
                        "help_text": setting_data["help_text"],
                        "is_public": False,  # All Stripe settings are internal
                        "is_active": True,
                    },
                )

                if created:
                    created_count += 1
                    status_icon = "✅"
                    status_text = "created"

                    # Log sensitive settings without revealing values
                    if setting_data["is_sensitive"] and setting_data["value"]:
                        self.stdout.write(f"{status_icon} {key}: {status_text} (encrypted)")
                    else:
                        self.stdout.write(f"{status_icon} {key}: {status_text} = {setting_data['value']}")

                elif force:
                    # Update existing setting
                    setting.name = setting_data["name"]
                    setting.description = setting_data["description"]
                    setting.data_type = setting_data["data_type"]
                    setting.is_sensitive = setting_data["is_sensitive"]
                    setting.is_required = setting_data["is_required"]
                    setting.help_text = setting_data["help_text"]

                    # Only update value if provided
                    if setting_data["value"]:
                        setting.value = str(setting_data["value"])

                    setting.save()
                    updated_count += 1

                    if setting_data["is_sensitive"] and setting_data["value"]:
                        self.stdout.write(f"🔄 {key}: updated (encrypted)")
                    else:
                        self.stdout.write(f"🔄 {key}: updated = {setting_data['value']}")
                else:
                    skipped_count += 1
                    self.stdout.write(f"⏭️  {key}: already exists (use --force to update)")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Failed to create setting {key}: {e}"))

        # Summary
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("📊 Stripe settings setup complete:"))
        self.stdout.write(f"  ✅ Created: {created_count}")
        self.stdout.write(f"  🔄 Updated: {updated_count}")
        self.stdout.write(f"  ⏭️  Skipped: {skipped_count}")

        if created_count > 0 or updated_count > 0:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING("🔒 Security Notes:"))
            self.stdout.write("  • Secret keys are automatically encrypted")
            self.stdout.write("  • Encrypted values are marked as (hidden) in admin")
            self.stdout.write("  • Use SettingsService.get() to access values in code")

        if not secret_key or not publishable_key or not webhook_secret:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING("⚠️  Missing Configuration:"))
            if not secret_key:
                self.stdout.write("  • Run again with --secret-key sk_...")
            if not publishable_key:
                self.stdout.write("  • Run again with --publishable-key pk_...")
            if not webhook_secret:
                self.stdout.write("  • Run again with --webhook-secret whsec_...")
            self.stdout.write("  • Use --enabled to activate Stripe integration")

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("💳 Stripe integration is ready to configure!"))
