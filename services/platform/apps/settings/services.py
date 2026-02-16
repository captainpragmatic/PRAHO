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
        # ── Company & Branding ──────────────────────────────────────────
        "company.legal_name": "PragmaticHost SRL",
        "company.registration_number": "",
        "company.address": "",
        "company.email_contact": "contact@pragmatichost.com",
        "company.email_support": "support@pragmatichost.com",
        "company.email_privacy": "privacy@pragmatichost.com",
        "company.email_dpo": "dpo@pragmatichost.com",
        "company.email_noreply": "noreply@pragmatichost.com",
        "company.phone": "",
        # ── Billing & Invoicing ─────────────────────────────────────────
        "billing.proforma_validity_days": 30,
        "billing.payment_grace_period_days": 5,
        "billing.invoice_payment_terms_days": 14,
        "billing.vat_rate": "0.21",
        "billing.max_payment_amount_cents": 100000000,
        "billing.payment_retry_attempts": 3,
        "billing.payment_retry_delay_hours": 24,
        "billing.negative_balance_threshold": "-100.00",
        "billing.subscription_grace_period_days": 7,
        "billing.max_payment_retry_attempts": 5,
        "billing.efactura_minimum_amount_cents": 10000,
        "billing.efactura_submission_deadline_days": 5,
        "billing.efactura_deadline_warning_hours": 24,
        "billing.efactura_batch_size": 100,
        "billing.efactura_api_max_retries": 3,
        "billing.efactura_api_timeout_seconds": 30,
        "billing.event_grace_period_hours": 24,
        "billing.future_event_drift_minutes": 5,
        "billing.alert_cooldown_hours": 24,
        "billing.task_retry_delay_seconds": 300,
        "billing.task_max_retries": 3,
        "billing.credit_consecutive_bonus_6": 10,
        "billing.credit_consecutive_bonus_12": 20,
        "billing.large_credit_limit_threshold": 10000,
        "billing.extended_payment_terms_threshold": 60,
        # ── Users & Authentication ──────────────────────────────────────
        "users.session_timeout_minutes": 120,
        "users.mfa_required_for_staff": True,
        # users.password_reset_timeout_hours removed — Django's PASSWORD_RESET_TIMEOUT (base.py) is authoritative
        "users.max_login_attempts": 5,
        "users.account_lockout_duration_minutes": 15,
        "users.admin_session_timeout_minutes": 30,
        "users.shared_device_timeout_minutes": 15,
        "users.backup_code_count": 10,
        "users.credential_max_age_days": 90,
        "users.credential_rotation_retry_limit": 3,
        "users.login_rate_limit_per_hour": 5,
        "users.security_lockout_failure_threshold": 5,
        # ── Domain Management ───────────────────────────────────────────
        "domains.registration_enabled": True,
        "domains.auto_renewal_enabled": True,
        "domains.renewal_notice_days": 30,
        "domains.expiry_critical_days": 7,
        "domains.expiry_warning_days": 30,
        "domains.max_per_package": 100,
        "domains.max_subdomains_per_domain": 50,
        "domains.whois_privacy_price_cents": 500,
        # ── Service Provisioning ────────────────────────────────────────
        "provisioning.auto_setup_enabled": True,
        "provisioning.setup_timeout_minutes": 30,
        "provisioning.suspend_timeout_minutes": 15,
        "provisioning.terminate_timeout_minutes": 60,
        "provisioning.default_disk_quota_gb": 10,
        "provisioning.default_bandwidth_quota_gb": 100,
        "provisioning.max_email_accounts_per_package": 50,
        "provisioning.recovery_excellent_threshold": 95,
        "provisioning.recovery_good_threshold": 90,
        "provisioning.recovery_warning_threshold": 80,
        "provisioning.max_backup_size_gb": 50,
        "provisioning.backup_retention_days": 90,
        "provisioning.high_value_plan_threshold_cents": 50000,
        "provisioning.resource_usage_alert_threshold": 85,
        "provisioning.server_overload_threshold": 90,
        "provisioning.long_provisioning_threshold_minutes": 30,
        # ── Virtualmin Integration ──────────────────────────────────────
        "virtualmin.hostname": "localhost",
        "virtualmin.port": 10000,
        "virtualmin.ssl_verify": True,
        "virtualmin.request_timeout_seconds": 30,
        "virtualmin.max_retries": 3,
        "virtualmin.rate_limit_qps": 10,
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
        "virtualmin.ssh_username": "virtualmin-praho",
        "virtualmin.api_endpoint_path": "/virtual-server/remote.cgi",
        "virtualmin.use_ssl": True,
        # ── Support & Tickets ───────────────────────────────────────────
        "tickets.sla_critical_response_hours": 1,
        "tickets.sla_high_response_hours": 4,
        "tickets.sla_standard_response_hours": 24,
        "tickets.sla_low_response_hours": 72,
        "tickets.auto_escalation_hours": 48,
        "tickets.max_reassignments": 3,
        "tickets.max_file_size_bytes": 2097152,
        "tickets.allowed_file_extensions": [".pdf", ".txt", ".png", ".jpg", ".jpeg", ".doc", ".docx"],
        "tickets.max_attachments_per_ticket": 5,
        "tickets.security_alert_threshold": 5,
        # ── Security & Access ───────────────────────────────────────────
        "security.rate_limit_per_hour": 1000,
        "security.require_2fa_for_admin": True,
        "security.api_burst_limit": 50,
        "security.max_customer_lookups_per_hour": 20,
        "security.suspicious_ip_threshold": 3,
        "security.registration_rate_limit_per_ip": 5,
        "security.invitation_rate_limit_per_user": 10,
        "security.company_check_rate_limit_per_ip": 30,
        # ── Monitoring & Alerts ─────────────────────────────────────────
        "monitoring.cpu_warning_threshold": 80,
        "monitoring.memory_warning_threshold": 85,
        "monitoring.disk_warning_threshold": 90,
        "monitoring.alert_cooldown_minutes": 60,
        "monitoring.health_check_interval_minutes": 5,
        # ── Notifications ───────────────────────────────────────────────
        "notifications.email_enabled": True,
        "notifications.sms_enabled": False,
        "notifications.max_recipients_per_batch": 50,
        "notifications.email_batch_size": 50,
        "notifications.digest_frequency_hours": 24,
        "notifications.max_history": 1000,
        "notifications.email_max_retries": 3,
        # ── GDPR & Data Retention ───────────────────────────────────────
        "gdpr.data_retention_years": 7,
        "gdpr.log_retention_months": 12,
        "gdpr.export_retention_days": 30,
        "gdpr.audit_log_retention_years": 10,
        "gdpr.failed_login_retention_months": 6,
        # ── External Integrations ───────────────────────────────────────
        "integrations.stripe_secret_key": "",
        "integrations.stripe_publishable_key": "",
        "integrations.stripe_webhook_secret": "",
        "integrations.stripe_enabled": False,
        "integrations.webhook_retry_attempts": 5,
        "integrations.webhook_timeout_seconds": 30,
        "integrations.webhook_batch_size": 50,
        "integrations.api_request_timeout_seconds": 30,
        "integrations.api_connection_timeout_seconds": 10,
        # ── UI & Display ────────────────────────────────────────────────
        "ui.default_page_size": 20,
        "ui.max_page_size": 100,
        "ui.min_page_size": 5,
        "ui.max_attachment_size_mb": 25,
        # ── Promotions & Discounts ──────────────────────────────────────
        "promotions.max_discount_percent": 100,
        "promotions.max_discount_amount_cents": 100000000,
        "promotions.max_coupon_batch_size": 1000,
        # ── System Configuration ────────────────────────────────────────
        "system.maintenance_mode": False,
        "system.backup_retention_days": 30,
        # ── Node Deployment ─────────────────────────────────────────────
        "node_deployment.terraform_state_backend": "local",
        "node_deployment.terraform_s3_bucket": "",
        "node_deployment.terraform_s3_region": "eu-west-1",
        "node_deployment.terraform_s3_key_prefix": "praho/nodes/",
        "node_deployment.dns_default_zone": "",
        "node_deployment.dns_cloudflare_zone_id": "",
        "node_deployment.dns_cloudflare_api_token": "",
        "node_deployment.default_provider": "hetzner",
        "node_deployment.default_region": "fsn1",
        "node_deployment.default_environment": "prd",
        "node_deployment.backup_enabled": True,
        "node_deployment.backup_storage": "local",
        "node_deployment.backup_s3_bucket": "",
        "node_deployment.backup_retention_days": 7,
        "node_deployment.backup_schedule": "0 2 * * *",
        "node_deployment.timeout_terraform_apply": 600,
        "node_deployment.timeout_ansible_playbook": 1800,
        "node_deployment.timeout_validation": 300,
        "node_deployment.enabled": True,
        "node_deployment.auto_registration": True,
        "node_deployment.cost_tracking_enabled": True,
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

        Uses select_for_update to prevent race conditions when multiple
        processes try to update the same setting simultaneously.

        Args:
            key: Setting key
            value: New value
            user_id: User making the change
            reason: Reason for the change

        Returns:
            Result with updated setting or validation error
        """
        from django.db import IntegrityError  # noqa: PLC0415

        try:
            # Infer data type
            data_type = cls._infer_data_type(value)

            # Prepare values for JSON serialization
            json_value = cls._prepare_value_for_json(value, data_type)
            json_default = cls._prepare_value_for_json(cls.DEFAULT_SETTINGS.get(key, value), data_type)

            # Try to get existing setting with lock first (most common case)
            try:
                setting = SystemSetting.objects.select_for_update().get(key=key)
                created = False
            except SystemSetting.DoesNotExist:
                # Setting doesn't exist - create it with proper race condition handling
                try:
                    setting = SystemSetting.objects.create(
                        key=key,
                        name=cls._generate_name_from_key(key),
                        description=f"System setting: {key}",
                        category=key.split(".", maxsplit=1)[0] if "." in key else "system",
                        data_type=data_type,
                        value=json_value,
                        default_value=json_default,
                    )
                    created = True
                except IntegrityError:
                    # Another process created it - get it with lock
                    setting = SystemSetting.objects.select_for_update().get(key=key)
                    created = False

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
