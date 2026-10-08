"""Fixtures for settings written before the current catalog validation existed."""

from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SystemSetting


def store_legacy_integer(key: str, value: int) -> None:
    """Bypass service validation to represent an already persisted legacy row."""
    SystemSetting.objects.update_or_create(
        key=key,
        defaults={
            "category": key.split(".", 1)[0],
            "data_type": "integer",
            "value": str(value),
            "default_value": str(CATALOG_BY_KEY[key].default),
        },
    )
