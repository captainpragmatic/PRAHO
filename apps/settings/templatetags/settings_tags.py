"""
Template tags for System Settings
Provides easy access to system settings in Django templates.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any

from django import template
from django.template.context import RequestContext
from django.utils.html import format_html
from django.utils.safestring import SafeString, mark_safe

from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService

logger = logging.getLogger(__name__)
register = template.Library()

# Template display constants  
MAX_BADGE_TEXT_LENGTH = 20  # Maximum characters to show in setting badge


@register.simple_tag(name='setting')
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


@register.simple_tag(name='setting_bool')
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


@register.simple_tag(name='setting_int')
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


@register.simple_tag(name='setting_decimal')
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


@register.simple_tag(name='setting_list')
def get_list_setting(key: str, default: list[Any] | None = None) -> list[Any]:
    """
    📋 Get list system setting with type safety
    
    Usage:
        {% setting_list "domains.allowed_extensions" %}
        {% setting_list "users.allowed_roles" default="user,admin" %}
    """
    try:
        return SettingsService.get_list_setting(key, default or [])
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting list setting %s: %s", key, str(e))
        return default or []


@register.simple_tag(name='settings_category')
def get_settings_category(category: str) -> dict[str, Any]:
    """
    📂 Get all settings for a category
    
    Usage:
        {% settings_category "billing" as billing_settings %}
        {{ billing_settings.proforma_validity_days }}
    """
    try:
        return SettingsService.get_settings_by_category(category)
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting category %s: %s", category, str(e))
        return {}


@register.inclusion_tag('settings/setting_display.html', takes_context=True)
def setting_display(context: RequestContext, key: str, label: str = '', show_default: bool = False) -> dict[str, Any]:
    """
    🎨 Display setting with proper formatting
    
    Usage:
        {% setting_display "billing.proforma_validity_days" label="Proforma Validity" %}
        {% setting_display "users.mfa_required_for_staff" show_default=True %}
    """
    try:
        # Try to get the full setting object for metadata
        try:
            setting = SystemSetting.objects.get(key=key)
            value = setting.get_typed_value()
            display_value = setting.get_display_value()
            default_value = setting.get_typed_default_value()
            data_type = setting.data_type
            description = setting.description
            help_text = setting.help_text
        except SystemSetting.DoesNotExist:
            # Fallback to service
            value = SettingsService.get_setting(key)
            display_value = str(value) if value is not None else "(not set)"
            default_value = SettingsService.DEFAULT_SETTINGS.get(key)
            data_type = "unknown"
            description = ""
            help_text = ""
        
        return {
            'key': key,
            'label': label or key.replace('_', ' ').title(),
            'value': value,
            'display_value': display_value,
            'default_value': default_value,
            'data_type': data_type,
            'description': description,
            'help_text': help_text,
            'show_default': show_default,
            'request': context.get('request'),
        }
        
    except Exception as e:
        logger.error("🔥 [Settings Template] Error displaying setting %s: %s", key, str(e))
        return {
            'key': key,
            'label': label or key,
            'value': None,
            'display_value': "(error)",
            'error': str(e)
        }


@register.filter(name='setting_badge')
def setting_badge(value: Any, data_type: str = 'string') -> SafeString:  # noqa: PLR0911 # Template formatting requires multiple return paths
    """
    🏷️ Generate a badge for setting value based on data type
    
    Usage:
        {{ setting_value|setting_badge:setting_type }}
    """
    try:
        if value is None:
            return mark_safe('<span class="badge bg-secondary">Not Set</span>')
        
        if data_type == 'boolean':
            if value:
                return mark_safe('<span class="badge bg-success">✅ Enabled</span>')
            else:
                return mark_safe('<span class="badge bg-danger">❌ Disabled</span>')
        elif data_type == 'integer':
            color = 'primary' if value > 0 else 'secondary'
            return format_html('<span class="badge bg-{}">🔢 {}</span>', color, value)
        elif data_type == 'decimal':
            return format_html('<span class="badge bg-info">💰 {}</span>', value)
        elif data_type == 'list':
            count = len(value) if isinstance(value, list) else 0
            return format_html('<span class="badge bg-warning">📋 {} items</span>', count)
        else:  # string, json, etc.
            display_value = str(value)[:MAX_BADGE_TEXT_LENGTH] + ('...' if len(str(value)) > MAX_BADGE_TEXT_LENGTH else '')
            return format_html('<span class="badge bg-light text-dark">📝 {}</span>', display_value)
            
    except Exception as e:
        logger.error("🔥 [Settings Template] Error creating badge for %s: %s", value, str(e))
        return mark_safe('<span class="badge bg-danger">Error</span>')


@register.simple_tag(name='is_feature_enabled')
def is_feature_enabled(feature_key: str) -> bool:
    """
    🚀 Check if a feature is enabled (boolean setting shortcut)
    
    Usage:
        {% is_feature_enabled "domains.registration_enabled" as domains_enabled %}
        {% if domains_enabled %}...{% endif %}
    """
    try:
        return SettingsService.get_boolean_setting(feature_key, False)
    except Exception as e:
        logger.error("🔥 [Settings Template] Error checking feature %s: %s", feature_key, str(e))
        return False


@register.simple_tag(name='maintenance_mode')
def is_maintenance_mode() -> bool:
    """
    🔧 Check if system is in maintenance mode
    
    Usage:
        {% maintenance_mode as is_maintenance %}
        {% if is_maintenance %}...{% endif %}
    """
    try:
        return SettingsService.get_boolean_setting('system.maintenance_mode', False)
    except Exception as e:
        logger.error("🔥 [Settings Template] Error checking maintenance mode: %s", str(e))
        return False


@register.inclusion_tag('settings/feature_flag.html')
def feature_flag(feature_key: str, enabled_content: str = '', disabled_content: str = '') -> dict[str, Any]:
    """
    🎛️ Feature flag template tag for conditional content
    
    Usage:
        {% feature_flag "domains.registration_enabled" %}
            Enabled content here
        {% endfeature_flag %}
    """
    try:
        is_enabled = SettingsService.get_boolean_setting(feature_key, False)
        
        return {
            'feature_key': feature_key,
            'is_enabled': is_enabled,
            'enabled_content': enabled_content,
            'disabled_content': disabled_content,
        }
        
    except Exception as e:
        logger.error("🔥 [Settings Template] Error with feature flag %s: %s", feature_key, str(e))
        return {
            'feature_key': feature_key,
            'is_enabled': False,
            'error': str(e)
        }


@register.simple_tag(takes_context=True, name='setting_for_user')
def get_setting_for_user(context: RequestContext, key: str, default: Any = None) -> Any:
    """
    👤 Get setting value with user context (for future user-specific settings)
    
    Usage:
        {% setting_for_user "users.session_timeout_minutes" %}
    """
    try:
        # For now, just use global settings
        # In the future, this could check for user-specific overrides
        user = context.get('user')
        
        # Add user-specific logic here in the future
        if user and user.is_authenticated:
            # Could check for user-specific setting overrides
            pass
        
        return SettingsService.get_setting(key, default)
        
    except Exception as e:
        logger.error("🔥 [Settings Template] Error getting user setting %s: %s", key, str(e))
        return default


@register.simple_tag(name='cache_setting')
def cache_and_get_setting(key: str, cache_timeout: int = 3600, default: Any = None) -> Any:
    """
    ⚡ Get setting with custom cache timeout
    
    Usage:
        {% cache_setting "expensive.calculated.value" cache_timeout=7200 %}
    """
    try:
        # The service already handles caching, but this allows custom timeouts
        # For now, just use the service default caching
        return SettingsService.get_setting(key, default)
        
    except Exception as e:
        logger.error("🔥 [Settings Template] Error caching setting %s: %s", key, str(e))
        return default
