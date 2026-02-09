"""
System Settings service layer for PRAHO Platform
Centralized configuration management with Redis caching and type safety.
"""

from __future__ import annotations

import decimal
import json
import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.cache import cache
from django.core.exceptions import ValidationError

from apps.common.security_decorators import (
    atomic_with_retry,
    audit_service_call,
    monitor_performance,
)
from apps.common.types import Err, Ok, Result

from .models import SystemSetting

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Type alias for setting values
SettingValue = str | int | bool | Decimal | list[Any] | dict[str, Any] | None

# Settings validation constants
SETTING_KEY_PARTS_COUNT = 2  # Expected parts in a setting key (category.name)


@dataclass
class SettingUpdate:
    """📝 Data structure for setting update operations"""

    key: str
    value: Any
    user_id: int | None = None
    reason: str | None = None


@dataclass
class SettingValidationError:
    """🚨 Setting validation error details"""

    key: str
    field: str
    message: str
    code: str


class SettingsService:
    """⚙️ Centralized settings management with caching and validation"""

    # Cache configuration
    CACHE_PREFIX: ClassVar[str] = "praho_setting"
    CACHE_TIMEOUT: ClassVar[int] = 3600  # 1 hour
    CACHE_VERSION: ClassVar[int] = 1

    # Default settings values
    DEFAULT_SETTINGS: ClassVar[dict[str, Any]] = {
        "billing.proforma_validity_days": 30,
        "billing.payment_grace_period_days": 5,
        "billing.invoice_due_days": 30,
        "billing.vat_rate": "0.21",
        "users.session_timeout_minutes": 120,
        "users.mfa_required_for_staff": True,
        "users.password_reset_timeout_hours": 24,
        "users.max_login_attempts": 5,
        "domains.registration_enabled": True,
        "domains.auto_renewal_enabled": True,
        "domains.renewal_notice_days": 30,
        "provisioning.auto_setup_enabled": True,
        "provisioning.setup_timeout_minutes": 30,
        # Virtualmin operational settings
        "virtualmin.hostname": "localhost",
        "virtualmin.port": 10000,
        "virtualmin.ssl_verify": True,
        "virtualmin.request_timeout_seconds": 30,
        "virtualmin.max_retries": 3,
        "virtualmin.rate_limit_qps": 10,
        # Stripe payment integration settings
        "integrations.stripe_secret_key": "",
        "integrations.stripe_publishable_key": "",
        "integrations.stripe_webhook_secret": "",
        "integrations.stripe_enabled": False,
        "virtualmin.connection_pool_size": 10,
        "virtualmin.rate_limit_max_calls_per_hour": 100,
        "virtualmin.auth_health_check_interval_seconds": 3600,
        "virtualmin.auth_fallback_enabled": True,
        "virtualmin.backup_retention_days": 7,
        "virtualmin.backup_compression_enabled": True,
        "virtualmin.domain_quota_default_mb": 1000,
        "virtualmin.bandwidth_quota_default_mb": 10000,
        "virtualmin.mysql_enabled": True,
        "virtualmin.postgresql_enabled": False,
        "virtualmin.php_version_default": "8.1",
        "virtualmin.ssl_auto_renewal_enabled": True,
        "virtualmin.monitoring_enabled": True,
        "virtualmin.log_retention_days": 30,
        # Advanced authentication settings
        "virtualmin.ssh_username": "virtualmin-praho",
        "virtualmin.api_endpoint_path": "/virtual-server/remote.cgi",
        "virtualmin.use_ssl": True,
        "security.rate_limit_per_hour": 1000,
        "security.require_2fa_for_admin": True,
        "notifications.email_enabled": True,
        "notifications.sms_enabled": False,
        "system.maintenance_mode": False,
        "system.backup_retention_days": 30,
        # Node Deployment settings - Infrastructure provisioning configuration
        # Terraform Configuration
        "node_deployment.terraform_state_backend": "local",  # 'local' or 's3'
        "node_deployment.terraform_s3_bucket": "",  # S3 bucket name (when backend=s3)
        "node_deployment.terraform_s3_region": "",  # S3 region (when backend=s3)
        "node_deployment.terraform_s3_key_prefix": "praho/nodes/",  # S3 key prefix
        # DNS Configuration
        "node_deployment.dns_default_zone": "",  # Default Cloudflare zone for node hostnames
        "node_deployment.dns_cloudflare_zone_id": "",  # Cloudflare zone ID
        "node_deployment.dns_cloudflare_api_token": "",  # Cloudflare API token (sensitive)
        # Default Deployment Options
        "node_deployment.default_provider": "hetzner",  # Default cloud provider
        "node_deployment.default_region": "fsn1",  # Default region code
        "node_deployment.default_environment": "prd",  # Default environment (prd/stg/dev)
        # Backup Configuration
        "node_deployment.backup_enabled": True,  # Enable backups on new nodes
        "node_deployment.backup_storage": "local",  # 'local' or 's3' (TODO: s3)
        "node_deployment.backup_s3_bucket": "",  # S3 bucket for backups (TODO)
        "node_deployment.backup_retention_days": 7,  # Local backup retention
        "node_deployment.backup_schedule": "0 2 * * *",  # Cron schedule (2 AM daily)
        # Timeouts (seconds)
        "node_deployment.timeout_terraform_apply": 600,  # 10 minutes
        "node_deployment.timeout_ansible_playbook": 1800,  # 30 minutes
        "node_deployment.timeout_validation": 300,  # 5 minutes
        # Feature flags
        "node_deployment.enabled": True,  # Master enable/disable for node deployment
        "node_deployment.auto_registration": True,  # Auto-register as VirtualminServer
        "node_deployment.cost_tracking_enabled": True,  # Track deployment costs
    }

    @classmethod
    def _get_cache_key(cls, key: str) -> str:
        """Generate cache key for setting"""
        return f"{cls.CACHE_PREFIX}:{key}"

    @classmethod
    @monitor_performance()
    def get_setting(cls, key: str, default: Any = None) -> SettingValue:
        """
        🔍 Get setting value with caching

        Args:
            key: Setting key (e.g., 'billing.proforma_validity_days')
            default: Default value if setting not found

        Returns:
            Setting value or default
        """
        # Generate cache key first (needed for both paths)
        cache_key = cls._get_cache_key(key)

        # Get from database first to check if sensitive
        try:
            setting = SystemSetting.objects.get(key=key)

            # For sensitive settings, always query database (no caching)
            if setting.is_sensitive:
                value = setting.get_typed_value()
                logger.debug("⚡ [Settings] Database hit for key: %s (sensitive, not cached)", key)
                return value

            # For non-sensitive settings, use cache
            cached_value = cache.get(cache_key, version=cls.CACHE_VERSION)

            if cached_value is not None:
                logger.debug("✅ [Settings] Cache hit for key: %s", key)
                return cached_value  # type: ignore[no-any-return]

            # Cache miss - get value and cache it
            value = setting.get_typed_value()
            cache.set(cache_key, value, timeout=cls.CACHE_TIMEOUT, version=cls.CACHE_VERSION)
            logger.debug("⚡ [Settings] Database hit for key: %s (cached)", key)

            return value

        except SystemSetting.DoesNotExist:
            # Use default from DEFAULT_SETTINGS or provided default
            fallback_value = cls.DEFAULT_SETTINGS.get(key, default)

            # Cache the default value temporarily
            cache.set(
                cache_key,
                fallback_value,
                timeout=300,  # 5 minutes for defaults
                version=cls.CACHE_VERSION,
            )

            logger.warning("⚠️ [Settings] Using default for missing key: %s", key)
            return fallback_value  # type: ignore[no-any-return]

    @classmethod
    @monitor_performance()
    def set_setting(cls, key: str, value: Any) -> None:
        """
        🔧 Set setting value and update cache

        Args:
            key: Setting key (e.g., "billing.proforma_validity_days")
            value: New value to set

        Raises:
            SystemSetting.DoesNotExist: If setting doesn't exist
            ValidationError: If value is invalid for the setting type
        """
        try:
            # Get the setting
            setting = SystemSetting.objects.get(key=key)

            # Validate and convert value based on data type
            if setting.data_type == "boolean":
                value = value.lower() in ("true", "1", "on", "yes") if isinstance(value, str) else bool(value)
            elif setting.data_type == "integer":
                value = int(value)
            elif setting.data_type == "decimal":
                value = Decimal(str(value))
            elif (setting.data_type in {"list", "json"}) and isinstance(value, str):
                value = json.loads(value)
            # string type needs no conversion

            # Prepare value for JSON serialization
            json_value = cls._prepare_value_for_json(value, setting.data_type)

            # Update the setting value
            setting.value = json_value
            setting.save()

            # Clear cache for this setting
            cache_key = cls._get_cache_key(key)
            cache.delete(cache_key, version=cls.CACHE_VERSION)

            logger.info("⚡ [Settings] Updated %s = %s", key, value)

        except Exception as e:
            logger.error("💥 [Settings] Error setting %s: %s", key, e)
            raise

    @classmethod
    @monitor_performance()
    def get_boolean_setting(cls, key: str, default: bool = False) -> bool:
        """🔄 Get boolean setting with type safety"""
        value = cls.get_setting(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes", "on")
        return bool(value)

    @classmethod
    @monitor_performance()
    def get_integer_setting(cls, key: str, default: int = 0) -> int:
        """🔢 Get integer setting with type safety"""
        value = cls.get_setting(key, default)
        try:
            return int(value)
        except (ValueError, TypeError):
            logger.warning("⚠️ [Settings] Invalid integer value for %s: %s", key, value)
            return default

    @classmethod
    @monitor_performance()
    def get_decimal_setting(cls, key: str, default: Decimal | None = None) -> Decimal:
        """💰 Get decimal setting with type safety"""
        value = cls.get_setting(key, default)
        try:
            return Decimal(str(value))
        except (ValueError, TypeError, decimal.InvalidOperation):
            logger.warning("⚠️ [Settings] Invalid decimal value for %s: %s", key, value)
            return default or Decimal("0")

    @classmethod
    @monitor_performance()
    def get_list_setting(cls, key: str, default: list[Any] | None = None) -> list[Any]:
        """📋 Get list setting with type safety"""
        value = cls.get_setting(key, default or [])
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                return [value]
        return default or []

    @classmethod
    @atomic_with_retry()
    @audit_service_call("setting_update")
    @monitor_performance()
    def update_setting(
        cls, key: str, value: Any, user_id: int | None = None, reason: str | None = None
    ) -> Result[SystemSetting, SettingValidationError]:
        """
        📝 Update system setting with validation and caching

        Args:
            key: Setting key
            value: New value
            user_id: User making the change
            reason: Reason for the change

        Returns:
            Result with updated setting or validation error
        """
        try:
            # Infer data type
            data_type = cls._infer_data_type(value)

            # Prepare values for JSON serialization
            json_value = cls._prepare_value_for_json(value, data_type)
            json_default = cls._prepare_value_for_json(cls.DEFAULT_SETTINGS.get(key, value), data_type)

            # Get or create setting
            setting, created = SystemSetting.objects.get_or_create(
                key=key,
                defaults={
                    "name": cls._generate_name_from_key(key),
                    "description": f"System setting: {key}",
                    "category": key.split(".")[0] if "." in key else "system",
                    "data_type": data_type,
                    "value": json_value,
                    "default_value": json_default,
                },
            )

            if not created:
                # Prepare value for JSON serialization
                json_value = cls._prepare_value_for_json(value, setting.data_type)
                # Update existing setting
                setting.value = json_value
                setting.full_clean()  # Validate
                setting.save(update_fields=["value", "updated_at"])

            # Clear cache
            cls._clear_setting_cache(key)

            # Log the change
            logger.info(
                "✅ [Settings] Updated setting %s to %s by user %s: %s",
                key,
                value if not setting.is_sensitive else "(hidden)",
                user_id or "system",
                reason or "no reason provided",
            )

            return Ok(setting)

        except ValidationError as e:
            error_msg = str(e.message_dict) if hasattr(e, "message_dict") else str(e)
            logger.error("🔥 [Settings] Validation error for %s: %s", key, error_msg)

            return Err(SettingValidationError(key=key, field="value", message=error_msg, code="validation_error"))

        except Exception as e:
            logger.error("🔥 [Settings] Unexpected error updating %s: %s", key, str(e))
            return Err(
                SettingValidationError(key=key, field="system", message=f"Unexpected error: {e!s}", code="system_error")
            )

    @classmethod
    def _prepare_value_for_json(cls, value: Any, data_type: str) -> Any:
        """Prepare value for JSON serialization based on data type"""
        if data_type == "decimal" and isinstance(value, Decimal):
            return str(value)
        elif data_type == "decimal" and not isinstance(value, Decimal):
            # Convert to Decimal first, then to string
            return str(Decimal(str(value)))
        return value

    @classmethod
    def _generate_name_from_key(cls, key: str) -> str:
        """Generate human-readable name from setting key"""
        return key.replace("_", " ").replace(".", " - ").title()

    @classmethod
    def _infer_data_type(cls, value: Any) -> str:
        """Infer data type from value"""
        if isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "integer"
        elif isinstance(value, float | Decimal):
            return "decimal"
        elif isinstance(value, list):
            return "list"
        elif isinstance(value, dict):
            return "json"
        else:
            return "string"

    @classmethod
    def _clear_setting_cache(cls, key: str) -> None:
        """Clear cached setting value"""
        cache_key = cls._get_cache_key(key)
        cache.delete(cache_key, version=cls.CACHE_VERSION)
        logger.debug("🧹 [Settings] Cleared cache for key: %s", key)

    @classmethod
    @monitor_performance()
    def bulk_update_settings(
        cls, updates: list[SettingUpdate], user_id: int | None = None
    ) -> Result[list[SystemSetting], list[SettingValidationError]]:
        """
        📦 Bulk update multiple settings

        Args:
            updates: List of setting updates
            user_id: User making the changes

        Returns:
            Result with updated settings or list of errors
        """
        updated_settings: list[SystemSetting] = []
        errors: list[SettingValidationError] = []

        for update in updates:
            result = cls.update_setting(
                key=update.key, value=update.value, user_id=user_id or update.user_id, reason=update.reason
            )

            if result.is_ok():
                updated_settings.append(result.value)
            else:
                errors.append(result.error)

        if errors:
            return Err(errors)

        logger.info("✅ [Settings] Bulk updated %d settings", len(updated_settings))
        return Ok(updated_settings)

    @classmethod
    @monitor_performance()
    def reset_setting_to_default(
        cls, key: str, user_id: int | None = None
    ) -> Result[SystemSetting, SettingValidationError]:
        """
        🔄 Reset setting to its default value

        Args:
            key: Setting key
            user_id: User making the change

        Returns:
            Result with reset setting or error
        """
        default_value = cls.DEFAULT_SETTINGS.get(key)
        if default_value is None:
            return Err(
                SettingValidationError(
                    key=key, field="default", message=f"No default value defined for setting: {key}", code="no_default"
                )
            )

        return cls.update_setting(key=key, value=default_value, user_id=user_id, reason="Reset to default value")  # type: ignore[no-any-return]

    @classmethod
    @monitor_performance()
    def get_settings_by_category(cls, category: str) -> dict[str, SettingValue]:
        """
        📂 Get all settings for a specific category

        Args:
            category: Setting category (e.g., 'billing')

        Returns:
            Dictionary of setting key -> value
        """
        try:
            settings = SystemSetting.objects.filter(category=category).select_related()
            result = {}

            for setting in settings:
                result[setting.key] = setting.get_typed_value()

            # Add any missing defaults for this category
            for key, default_value in cls.DEFAULT_SETTINGS.items():
                if key.startswith(f"{category}.") and key not in result:
                    result[key] = default_value

            logger.debug("📂 [Settings] Retrieved %d settings for category: %s", len(result), category)
            return result

        except Exception as e:
            logger.error("🔥 [Settings] Error getting settings for category %s: %s", category, str(e))
            return {}

    @classmethod
    @monitor_performance()
    def clear_all_cache(cls) -> None:
        """🧹 Clear all settings cache"""
        # Get all setting keys from database
        try:
            keys = SystemSetting.objects.values_list("key", flat=True)
            cleared_count = 0

            for key in keys:
                cache_key = cls._get_cache_key(key)
                if cache.delete(cache_key, version=cls.CACHE_VERSION):
                    cleared_count += 1

            logger.info("🧹 [Settings] Cleared %d cached settings", cleared_count)

        except Exception as e:
            logger.error("🔥 [Settings] Error clearing cache: %s", str(e))

    @classmethod
    def validate_setting_key(cls, key: str) -> bool:
        """🔍 Validate setting key format"""
        if not key or "." not in key:
            return False

        parts = key.split(".")
        if len(parts) != SETTING_KEY_PARTS_COUNT:
            return False

        category, name = parts
        return category.isalnum() and name.replace("_", "").replace("-", "").isalnum()

    @classmethod
    def get_settings_info(cls) -> dict[str, dict[str, Any]]:
        """📊 Get system settings information for monitoring"""
        try:
            total_settings = SystemSetting.objects.count()
            categories = SystemSetting.objects.values("category").distinct().count()

            # Cache statistics
            cached_keys = 0
            for key in cls.DEFAULT_SETTINGS:
                cache_key = cls._get_cache_key(key)
                if cache.get(cache_key, version=cls.CACHE_VERSION) is not None:
                    cached_keys += 1

            return {
                "database": {
                    "total_settings": total_settings,
                    "categories": categories,
                },
                "cache": {
                    "cached_keys": cached_keys,
                    "cache_timeout": cls.CACHE_TIMEOUT,
                    "cache_prefix": cls.CACHE_PREFIX,
                },
                "defaults": {
                    "total_defaults": len(cls.DEFAULT_SETTINGS),
                },
            }

        except Exception as e:
            logger.error("🔥 [Settings] Error getting settings info: %s", str(e))
            return {}


# ===============================================================================
# JSON SECURITY UTILITIES
# ===============================================================================

MAX_JSON_SIZE = 1024 * 1024  # 1MB limit
MAX_JSON_DEPTH = 10  # Prevent stack overflow


def _safe_json_loads(json_string: str) -> Any:
    """🔒 Safely parse JSON with size and depth limits to prevent DoS attacks"""

    # Check size limit
    if len(json_string.encode("utf-8")) > MAX_JSON_SIZE:
        raise ValidationError("JSON too large - exceeds 1MB limit")

    # Parse with depth checking
    def parse_with_depth_check(obj: Any, current_depth: int = 0) -> Any:
        if current_depth > MAX_JSON_DEPTH:
            raise ValidationError("JSON too deeply nested")

        if isinstance(obj, dict):
            return {k: parse_with_depth_check(v, current_depth + 1) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [parse_with_depth_check(item, current_depth + 1) for item in obj]
        else:
            return obj

    try:
        # First parse the JSON normally
        parsed_data = json.loads(json_string)

        # Then check depth recursively
        return parse_with_depth_check(parsed_data)

    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON format: {e!s}") from e
    except RecursionError as e:
        raise ValidationError(f"JSON nesting too deep - exceeds {MAX_JSON_DEPTH} levels") from e
