"""
Django management command to set up default setting categories
Creates all default setting categories for the PRAHO Platform
"""

from typing import Any, ClassVar

from django.core.management.base import BaseCommand, CommandParser

from apps.settings.models import SettingCategory


class Command(BaseCommand):
    """🏷️ Set up default setting categories for PRAHO Platform"""

    help = "Set up default setting categories for PRAHO Platform"

    # Default categories configuration
    DEFAULT_CATEGORIES: ClassVar[list[dict[str, Any]]] = [
        {
            "key": "billing",
            "name": "💰 Billing & Invoicing",
            "description": "Invoice settings, VAT rates, payment terms, and billing automation",
            "display_order": 10,
        },
        {
            "key": "users",
            "name": "👥 Users & Authentication",
            "description": "User management, 2FA settings, session timeouts, and access control",
            "display_order": 20,
        },
        {
            "key": "domains",
            "name": "🌐 Domain Management",
            "description": "Domain registration, renewal settings, and registrar configurations",
            "display_order": 30,
        },
        {
            "key": "provisioning",
            "name": "🚀 Service Provisioning",
            "description": "Hosting services automation, server management, and resource allocation",
            "display_order": 40,
        },
        {
            "key": "company",
            "name": "🏢 Company & Branding",
            "description": "Legal entity details, contact information, and branding configuration",
            "display_order": 5,
        },
        {
            "key": "virtualmin",
            "name": "🖥️ Virtualmin Integration",
            "description": "Virtualmin server configuration, API settings, and hosting account management",
            "display_order": 50,
        },
        {
            "key": "tickets",
            "name": "🎫 Support & Tickets",
            "description": "SLA response times, file upload limits, escalation rules, and support policies",
            "display_order": 55,
        },
        {
            "key": "security",
            "name": "🔒 Security & Access",
            "description": "Security policies, rate limiting, audit settings, and access controls",
            "display_order": 60,
        },
        {
            "key": "monitoring",
            "name": "📊 Monitoring & Alerts",
            "description": "Resource thresholds, health checks, alert cooldowns, and monitoring intervals",
            "display_order": 65,
        },
        {
            "key": "notifications",
            "name": "📧 Notifications",
            "description": "Email templates, SMS settings, notification delivery, and alert configurations",
            "display_order": 70,
        },
        {
            "key": "gdpr",
            "name": "🗄️ GDPR & Data Retention",
            "description": "Data retention policies, audit log lifetimes, and GDPR compliance settings",
            "display_order": 75,
        },
        {
            "key": "integrations",
            "name": "🔗 External Integrations",
            "description": "Payment gateways, webhooks, API keys, and third-party service configurations",
            "display_order": 80,
        },
        {
            "key": "ui",
            "name": "🖥️ UI & Display",
            "description": "Pagination defaults, page size limits, and display preferences",
            "display_order": 85,
        },
        {
            "key": "promotions",
            "name": "🎁 Promotions & Discounts",
            "description": "Discount limits, coupon batch sizes, and promotion constraints",
            "display_order": 88,
        },
        {
            "key": "system",
            "name": "⚙️ System Configuration",
            "description": "Platform-wide settings, maintenance mode, backup settings, and system preferences",
            "display_order": 90,
        },
    ]

    def add_arguments(self, parser: CommandParser) -> None:
        """Add command line arguments"""
        parser.add_argument(
            "--force",
            action="store_true",
            help="Force update existing categories with new data",
        )
        parser.add_argument(
            "--category",
            type=str,
            help="Only set up specific category by key",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """Execute the command"""
        force = options.get("force", False)
        category_filter = options.get("category")

        self.stdout.write(self.style.SUCCESS("🏷️ Setting up default setting categories..."))

        created_count = 0
        updated_count = 0
        skipped_count = 0

        categories_to_create = self.DEFAULT_CATEGORIES
        if category_filter:
            categories_to_create = [cat for cat in self.DEFAULT_CATEGORIES if cat["key"] == category_filter]

        for category_data in categories_to_create:
            try:
                category, created = SettingCategory.objects.get_or_create(
                    key=category_data["key"],
                    defaults={
                        "name": category_data["name"],
                        "description": category_data["description"],
                        "display_order": category_data["display_order"],
                        "is_active": True,
                    },
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"  ✅ Created category: {category_data['key']} - {category_data['name']}")
                elif force:
                    # Update existing category
                    category.name = category_data["name"]
                    category.description = category_data["description"]
                    category.display_order = category_data["display_order"]
                    category.save(update_fields=["name", "description", "display_order", "updated_at"])
                    updated_count += 1
                    self.stdout.write(f"  🔄 Updated category: {category_data['key']} - {category_data['name']}")
                else:
                    skipped_count += 1
                    self.stdout.write(f"  ⏭️  Skipped existing: {category_data['key']} (use --force to update)")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  🔥 Error setting up category {category_data['key']}: {e}"))
                continue

        # Summary
        self.stdout.write(self.style.SUCCESS("\n📊 Categories Setup Summary:"))
        self.stdout.write(f"  • Created: {created_count} categories")
        self.stdout.write(f"  • Updated: {updated_count} categories")
        self.stdout.write(f"  • Skipped: {skipped_count} categories")

        if category_filter:
            self.stdout.write(f"  • Category filter: {category_filter}")

        self.stdout.write(self.style.SUCCESS("✅ Default setting categories setup completed!"))

        # Helpful tip for next steps
        if created_count > 0:
            self.stdout.write(self.style.WARNING("\n💡 Next steps:"))
            self.stdout.write("  • Run 'python manage.py setup_default_settings' to create default settings")
            self.stdout.write("  • Visit /settings/dashboard/ to configure your platform")
