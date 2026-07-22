"""
Template tags for System Settings
Provides easy access to system settings in Django templates.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, cast

from django import template

from apps.settings.services import SettingsService

logger = logging.getLogger(__name__)
register = template.Library()


@register.simple_tag(name="setting")
def get_setting(key: str, default: Any = None) -> Any:
    """
    ⚙️ Get system setting value

    Usage:
        {% setting "billing.proforma_validity_days" %}
        {% setting "users.mfa_required_for_staff" default=False %}
    """
    try:
        return SettingsService.get_setting(key, default)
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting setting %s: %s", key, str(e))
        return default


@register.simple_tag(name="setting_bool")
def get_boolean_setting(key: str, default: bool = False) -> bool:
    """
    ✅ Get boolean system setting with type safety

    Usage:
        {% setting_bool "users.mfa_required_for_staff" %}
        {% setting_bool "domains.registration_enabled" default=True %}
    """
    try:
        return SettingsService.get_boolean_setting(key, default)
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting boolean setting %s: %s", key, str(e))
        return default


@register.simple_tag(name="setting_int")
def get_integer_setting(key: str, default: int = 0) -> int:
    """
    🔢 Get integer system setting with type safety

    Usage:
        {% setting_int "billing.proforma_validity_days" %}
        {% setting_int "users.session_timeout_minutes" default=120 %}
    """
    try:
        return SettingsService.get_integer_setting(key, default)
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting integer setting %s: %s", key, str(e))
        return default


@register.simple_tag(name="setting_decimal")
def get_decimal_setting(key: str, default: str = "0") -> str:
    """
    💰 Get decimal system setting with type safety

    Usage:
        {% setting_decimal "billing.vat_rate" %}
        {% setting_decimal "billing.late_fee_rate" default="0.05" %}
    """
    try:
        default_decimal = Decimal(str(default)) if default else None
        value = SettingsService.get_decimal_setting(key, default_decimal)
        return str(value)
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting decimal setting %s: %s", key, str(e))
        return default


@register.simple_tag(name="setting_list")
def get_list_setting(key: str, default: list[Any] | None = None) -> list[Any]:
    """
    📋 Get list system setting with type safety

    Usage:
        {% setting_list "domains.allowed_extensions" %}
        {% setting_list "users.allowed_roles" default="user,admin" %}
    """
    try:
        return cast(list[str], SettingsService.get_list_setting(key, default or []))
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting list setting %s: %s", key, str(e))
        return default or []


@register.simple_tag(name="settings_category")
def get_settings_category(category: str) -> dict[str, Any]:
    """
    📂 Get all settings for a category

    Usage:
        {% settings_category "billing" as billing_settings %}
        {{ billing_settings.proforma_validity_days }}
    """
    try:
        return cast(dict[str, Any], SettingsService.get_settings_by_category(category))
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting category %s: %s", category, str(e))
        return {}
