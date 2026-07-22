"""
Django management command that syncs SystemSetting rows with the settings catalog.

Creates missing rows and reconciles catalog-owned metadata (name, description,
help text, data type, sensitivity) on existing rows. Values are only touched
with --force. Idempotent: a second run reports zero changes.
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from apps.settings.catalog import CATALOG, SettingDef
from apps.settings.models import SystemSetting

# Metadata fields the catalog owns on every row
_METADATA_FIELDS = ("name", "description", "help_text", "data_type", "is_sensitive", "is_required", "category")


def _row_defaults(definition: SettingDef) -> dict[str, Any]:
    """Catalog-owned row attributes for one setting"""
    return {
        "name": definition.label,
        "description": definition.help_text or f"System setting: {definition.key}",
        "help_text": definition.help_text,
        "category": definition.group,
        "data_type": definition.data_type,
        "is_sensitive": definition.sensitive,
        "is_required": bool(definition.validation and definition.validation.get("required")),
        "default_value": definition.default,
    }


class Command(BaseCommand):
    """⚙️ Sync system settings with the catalog"""

    help = "Create missing settings and reconcile catalog-owned metadata (values only with --force)"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--force", action="store_true", help="Also reset values to catalog defaults")
        parser.add_argument("--category", type=str, help="Only sync settings for a specific group")

    def handle(self, *args: Any, **options: Any) -> None:
        force = options.get("force", False)
        category_filter = options.get("category")

        self.stdout.write(self.style.SUCCESS("🚀 Syncing system settings with the catalog..."))
        created = updated = unchanged = 0

        for definition in CATALOG:
            if category_filter and definition.group != category_filter:
                continue

            defaults = _row_defaults(definition)
            setting, was_created = SystemSetting.objects.get_or_create(
                key=definition.key,
                defaults={**defaults, "value": definition.default},
            )
            if was_created:
                created += 1
                self.stdout.write(f"  ✅ Created: {definition.key}")
                continue

            dirty_fields = []
            # A sensitive→plain transition must decrypt the stored value first,
            # otherwise the row keeps ciphertext that nothing will ever decrypt.
            if setting.is_sensitive and not defaults["is_sensitive"]:
                from apps.common.encryption import decrypt_value, is_encrypted  # noqa: PLC0415

                if setting.value is not None and is_encrypted(str(setting.value)):
                    setting.value = decrypt_value(str(setting.value))
                    dirty_fields.append("value")
            for field_name in _METADATA_FIELDS:
                if getattr(setting, field_name) != defaults[field_name]:
                    setattr(setting, field_name, defaults[field_name])
                    dirty_fields.append(field_name)
            if setting.default_value != defaults["default_value"]:
                setting.default_value = defaults["default_value"]
                dirty_fields.append("default_value")
            if force and setting.value != definition.default:
                setting.value = definition.default
                dirty_fields.append("value")

            if dirty_fields:
                setting.save(update_fields=[*dirty_fields, "updated_at"])
                updated += 1
                self.stdout.write(f"  🔄 Reconciled: {definition.key} ({', '.join(dirty_fields)})")
            else:
                unchanged += 1

        self.stdout.write(self.style.SUCCESS("\n📊 Sync summary:"))
        self.stdout.write(f"  • Created: {created}")
        self.stdout.write(f"  • Reconciled: {updated}")
        self.stdout.write(f"  • Unchanged: {unchanged}")
        self.stdout.write(self.style.SUCCESS("✅ Settings catalog sync complete!"))
