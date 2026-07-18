"""Create the database-backed settings used by the e-Factura integration."""

from __future__ import annotations

from typing import Any, NotRequired, TypedDict

from django.core.management.base import BaseCommand, CommandParser
from django.db import transaction

from apps.billing.efactura.settings import EFACTURA_DEFAULTS, EFacturaSettingKeys
from apps.settings.models import SystemSetting


class SettingDefinition(TypedDict):
    key: str
    name: str
    description: str
    category: str
    data_type: str
    is_sensitive: NotRequired[bool]
    is_required: NotRequired[bool]


_DECIMAL_SETTINGS = {
    EFacturaSettingKeys.VAT_RATE_STANDARD,
    EFacturaSettingKeys.VAT_RATE_REDUCED_1,
    EFacturaSettingKeys.VAT_RATE_REDUCED_2,
    EFacturaSettingKeys.VAT_RATE_ZERO,
}
_SENSITIVE_SETTINGS = {EFacturaSettingKeys.CLIENT_SECRET}
_REQUIRED_SETTINGS = {
    EFacturaSettingKeys.CLIENT_ID,
    EFacturaSettingKeys.CLIENT_SECRET,
    EFacturaSettingKeys.COMPANY_CUI,
    EFacturaSettingKeys.COMPANY_NAME,
}


def _data_type(default_value: Any, key: str) -> str:
    if key in _DECIMAL_SETTINGS:
        return "decimal"
    if isinstance(default_value, bool):
        return "boolean"
    if isinstance(default_value, int):
        return "integer"
    return "string"


def _definition(key: str, default_value: Any) -> SettingDefinition:
    readable_name = key.removeprefix("efactura.").replace(".", " ").replace("_", " ").title()
    return {
        "key": key,
        "name": readable_name,
        "description": f"Runtime e-Factura configuration for {readable_name.lower()}.",
        "category": "efactura",
        "data_type": _data_type(default_value, key),
        "is_sensitive": key in _SENSITIVE_SETTINGS,
        "is_required": key in _REQUIRED_SETTINGS,
    }


class Command(BaseCommand):
    """Set up every database-backed e-Factura runtime setting."""

    help = "Set up e-Factura settings in the SystemSetting model"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--force", action="store_true", help="Overwrite existing settings")
        parser.add_argument("--dry-run", action="store_true", help="Show changes without writing them")

    @transaction.atomic
    def handle(self, *args: object, **options: object) -> None:
        force = bool(options.get("force", False))
        dry_run = bool(options.get("dry_run", False))
        created_count = 0
        updated_count = 0
        skipped_count = 0

        for key, default_value in EFACTURA_DEFAULTS.items():
            definition = _definition(key, default_value)
            existing = SystemSetting.objects.filter(key=key).first()

            if dry_run:
                action = "update" if existing and force else "skip" if existing else "create"
                self.stdout.write(f"[DRY-RUN] {action}: {key} = {default_value}")
                continue

            if existing and not force:
                skipped_count += 1
                self.stdout.write(f"Skipping existing: {key}")
                continue

            _, created = SystemSetting.objects.update_or_create(
                key=key,
                defaults={
                    "name": definition["name"],
                    "description": definition["description"],
                    "category": definition["category"],
                    "data_type": definition["data_type"],
                    "value": default_value,
                    "default_value": default_value,
                    "is_sensitive": definition.get("is_sensitive", False),
                    "is_required": definition.get("is_required", False),
                },
            )
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f"Created: {key}"))
            else:
                updated_count += 1
                self.stdout.write(self.style.WARNING(f"Updated: {key}"))

        self.stdout.write(
            self.style.SUCCESS(f"Done! Created: {created_count}, Updated: {updated_count}, Skipped: {skipped_count}")
        )
