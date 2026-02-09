"""
Django management command to setup e-Factura settings.

Creates default e-Factura settings in the database using the
SystemSetting model from the settings app.

Usage:
    python manage.py setup_efactura_settings
    python manage.py setup_efactura_settings --force  # Overwrite existing
"""

from __future__ import annotations

import logging

from django.core.management.base import BaseCommand, CommandParser

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Setup e-Factura settings in the database."""

    help = "Setup e-Factura settings in the SystemSetting model"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--force",
            action="store_true",
            help="Overwrite existing settings",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without making changes",
        )

    def handle(self, *args: object, **options: object) -> None:
        force = options.get("force", False)
        dry_run = options.get("dry_run", False)

        try:
            from apps.settings.models import SystemSetting
        except ImportError:
            self.stderr.write(
                self.style.ERROR(
                    "Settings app not available. "
                    "Please ensure apps.settings is installed."
                )
            )
            return

        from apps.billing.efactura.settings import (
            EFACTURA_DEFAULTS,
            EFacturaSettingKeys,
        )

        # Setting definitions with metadata
        settings_definitions = [
            # General
            {
                "key": EFacturaSettingKeys.ENABLED,
                "name": "e-Factura Enabled",
                "description": "Enable or disable e-Factura integration",
                "category": "efactura",
                "data_type": "boolean",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.ENVIRONMENT,
                "name": "e-Factura Environment",
                "description": "ANAF environment: 'test' for sandbox, 'production' for live",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            # OAuth2
            {
                "key": EFacturaSettingKeys.CLIENT_ID,
                "name": "OAuth Client ID",
                "description": "ANAF OAuth2 client ID from application registration",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": True,
                "is_required": True,
            },
            {
                "key": EFacturaSettingKeys.CLIENT_SECRET,
                "name": "OAuth Client Secret",
                "description": "ANAF OAuth2 client secret from application registration",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": True,
                "is_required": True,
            },
            {
                "key": EFacturaSettingKeys.REDIRECT_URI,
                "name": "OAuth Redirect URI",
                "description": "OAuth2 callback URL registered with ANAF",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            # Company
            {
                "key": EFacturaSettingKeys.COMPANY_CUI,
                "name": "Company CUI",
                "description": "Company tax identification number (CUI)",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
                "is_required": True,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_NAME,
                "name": "Company Name",
                "description": "Legal company name as registered",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
                "is_required": True,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_REGISTRATION,
                "name": "Company Registration Number",
                "description": "Company registration number (J number)",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_STREET,
                "name": "Company Street Address",
                "description": "Company street address",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_CITY,
                "name": "Company City",
                "description": "Company city",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_POSTAL_CODE,
                "name": "Company Postal Code",
                "description": "Company postal code",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_COUNTRY,
                "name": "Company Country Code",
                "description": "Company country code (default: RO)",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_EMAIL,
                "name": "Company Email",
                "description": "Company contact email",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_PHONE,
                "name": "Company Phone",
                "description": "Company contact phone",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_BANK_ACCOUNT,
                "name": "Company Bank Account",
                "description": "Company IBAN for payment",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.COMPANY_BANK_NAME,
                "name": "Company Bank Name",
                "description": "Name of the bank",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
            # VAT Rates
            {
                "key": EFacturaSettingKeys.VAT_RATE_STANDARD,
                "name": "Standard VAT Rate",
                "description": "Standard VAT rate in Romania (default: 19%)",
                "category": "efactura",
                "data_type": "decimal",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.VAT_RATE_REDUCED_1,
                "name": "Reduced VAT Rate 1",
                "description": "First reduced VAT rate (default: 9% for hospitality)",
                "category": "efactura",
                "data_type": "decimal",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.VAT_RATE_REDUCED_2,
                "name": "Reduced VAT Rate 2",
                "description": "Second reduced VAT rate (default: 5% for food, books)",
                "category": "efactura",
                "data_type": "decimal",
                "is_sensitive": False,
            },
            # B2B/B2C
            {
                "key": EFacturaSettingKeys.B2B_ENABLED,
                "name": "B2B e-Factura Enabled",
                "description": "Enable B2B e-Factura (mandatory since Jan 2024)",
                "category": "efactura",
                "data_type": "boolean",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.B2C_ENABLED,
                "name": "B2C e-Factura Enabled",
                "description": "Enable B2C e-Factura (mandatory from Jan 2025)",
                "category": "efactura",
                "data_type": "boolean",
                "is_sensitive": False,
            },
            # Submission
            {
                "key": EFacturaSettingKeys.SUBMISSION_DEADLINE_DAYS,
                "name": "Submission Deadline Days",
                "description": "Days to submit invoice to ANAF (default: 5)",
                "category": "efactura",
                "data_type": "integer",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.AUTO_SUBMIT_ENABLED,
                "name": "Auto-Submit Enabled",
                "description": "Automatically submit invoices to e-Factura",
                "category": "efactura",
                "data_type": "boolean",
                "is_sensitive": False,
            },
            # Retry
            {
                "key": EFacturaSettingKeys.MAX_RETRIES,
                "name": "Maximum Retries",
                "description": "Maximum retry attempts for failed submissions",
                "category": "efactura",
                "data_type": "integer",
                "is_sensitive": False,
            },
            # Rate Limits
            {
                "key": EFacturaSettingKeys.RATE_LIMIT_GLOBAL_PER_MINUTE,
                "name": "Global Rate Limit (per minute)",
                "description": "ANAF global rate limit per minute",
                "category": "efactura",
                "data_type": "integer",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.RATE_LIMIT_STATUS_PER_MESSAGE_DAY,
                "name": "Status Rate Limit (per message/day)",
                "description": "Max status queries per message per day",
                "category": "efactura",
                "data_type": "integer",
                "is_sensitive": False,
            },
            # Validation
            {
                "key": EFacturaSettingKeys.XSD_VALIDATION_ENABLED,
                "name": "XSD Validation Enabled",
                "description": "Enable XSD schema validation",
                "category": "efactura",
                "data_type": "boolean",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.SCHEMATRON_VALIDATION_ENABLED,
                "name": "Schematron Validation Enabled",
                "description": "Enable CIUS-RO schematron validation",
                "category": "efactura",
                "data_type": "boolean",
                "is_sensitive": False,
            },
            # Metrics
            {
                "key": EFacturaSettingKeys.METRICS_ENABLED,
                "name": "Metrics Collection Enabled",
                "description": "Enable Prometheus metrics collection",
                "category": "efactura",
                "data_type": "boolean",
                "is_sensitive": False,
            },
            {
                "key": EFacturaSettingKeys.METRICS_PREFIX,
                "name": "Metrics Prefix",
                "description": "Prefix for Prometheus metric names",
                "category": "efactura",
                "data_type": "string",
                "is_sensitive": False,
            },
        ]

        created_count = 0
        updated_count = 0
        skipped_count = 0

        for setting_def in settings_definitions:
            key = setting_def["key"]
            default_value = EFACTURA_DEFAULTS.get(key)

            if dry_run:
                exists = SystemSetting.objects.filter(key=key).exists()
                action = "update" if exists and force else "create" if not exists else "skip"
                self.stdout.write(f"[DRY-RUN] {action}: {key} = {default_value}")
                continue

            try:
                existing = SystemSetting.objects.filter(key=key).first()

                if existing and not force:
                    skipped_count += 1
                    self.stdout.write(f"⏭️  Skipping existing: {key}")
                    continue

                _setting, created = SystemSetting.objects.update_or_create(
                    key=key,
                    defaults={
                        "name": setting_def["name"],
                        "description": setting_def["description"],
                        "category": setting_def.get("category", "efactura"),
                        "data_type": setting_def.get("data_type", "string"),
                        "value": default_value,
                        "default_value": default_value,
                        "is_sensitive": setting_def.get("is_sensitive", False),
                        "is_required": setting_def.get("is_required", False),
                    },
                )

                if created:
                    created_count += 1
                    self.stdout.write(self.style.SUCCESS(f"✅ Created: {key}"))
                else:
                    updated_count += 1
                    self.stdout.write(self.style.WARNING(f"🔄 Updated: {key}"))

            except Exception as e:
                self.stderr.write(self.style.ERROR(f"❌ Error setting {key}: {e}"))

        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS(
                f"Done! Created: {created_count}, Updated: {updated_count}, Skipped: {skipped_count}"
            )
        )
