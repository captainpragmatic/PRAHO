"""Resolve monetary alert thresholds without comparing different currencies."""

from apps.settings.services import SettingsService


def get_currency_threshold_cents(key: str, currency_code: str, *, legacy_ron_threshold: int) -> int:
    """An unknown threshold requests attention; the old scalar belongs to RON."""
    configured = SettingsService.get_setting(key, {})
    if isinstance(configured, dict) and currency_code in configured:
        value = configured[currency_code]
        return value if type(value) is int and value >= 0 else 0
    if currency_code == "RON":
        return max(0, legacy_ron_threshold)
    return 0
