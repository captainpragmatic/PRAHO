"""
System Settings service layer for PRAHO Platform
Centralized configuration management with Redis caching and type safety.
"""

from __future__ import annotations

import decimal
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils.translation import gettext_lazy as _

from apps.common.security_decorators import (
    atomic_with_retry,
    audit_service_call,
    monitor_performance,
)
from apps.common.types import Err, Ok, Result

from .catalog import CATALOG_BY_KEY, is_sensitive_key, validation_rules_for_key
from .catalog import DEFAULTS as CATALOG_DEFAULTS
from .models import SystemSetting

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Type alias for setting values
SettingValue = str | int | bool | Decimal | list[Any] | dict[str, Any] | None

# Settings validation constants
SETTING_KEY_MIN_PARTS = 2  # category.name
SETTING_KEY_MAX_PARTS = 3  # category.section.name (e-Factura namespace)

# Registry defaults are cached briefly so a later row creation becomes visible fast
DEFAULT_FALLBACK_CACHE_TIMEOUT = 300

# Distinguishes "cached None" from a cache miss; never stored, only used as cache.get default
_CACHE_MISS: Final = object()

_TRUTHY_STRINGS: Final = frozenset({"true", "1", "on", "yes"})
_FALSY_STRINGS: Final = frozenset({"false", "0", "off", "no", ""})


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


@dataclass
class ChangeSetConflict:
    """⚠️ Change-set entry whose baseline no longer matches the database"""

    key: str
    server_updated_at: str | None


@dataclass
class ChangeSetError:
    """🚨 Aggregate failure of a change-set application"""

    code: str  # "empty" | "validation" | "conflict"
    errors: list[SettingValidationError] = field(default_factory=list)
    conflicts: list[ChangeSetConflict] = field(default_factory=list)


@dataclass
class ChangeSetOutcome:
    """✅ Applied change set — fresh rows for the UI to rebaseline on"""

    change_set_id: str
    settings: dict[str, SystemSetting]


class SettingsService:
    """⚙️ Centralized settings management with caching and validation"""

    # Cache configuration
    CACHE_PREFIX: ClassVar[str] = "praho_setting"
    CACHE_TIMEOUT: ClassVar[int] = 3600  # 1 hour
    CACHE_VERSION: ClassVar[int] = 1

    # Single source of truth: the settings catalog (ADR-0042)
    DEFAULT_SETTINGS: ClassVar[dict[str, Any]] = dict(CATALOG_DEFAULTS)

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
        # Cache first (ADR-0015 tier order). Sensitive settings are never written
        # to the cache, so a cache hit is always safe to return directly.
        cache_key = cls._get_cache_key(key)
        cached_value = cache.get(cache_key, _CACHE_MISS, version=cls.CACHE_VERSION)
        if cached_value is not _CACHE_MISS:
            logger.debug("✅ [Settings] Cache hit for key: %s", key)
            return cast("SettingValue", cached_value)

        try:
            setting = SystemSetting.objects.get(key=key)
        except SystemSetting.DoesNotExist:
            fallback_value = cls.DEFAULT_SETTINGS.get(key, default)
            cache.set(cache_key, fallback_value, timeout=DEFAULT_FALLBACK_CACHE_TIMEOUT, version=cls.CACHE_VERSION)
            logger.warning("⚠️ [Settings] Using default for missing key: %s", key)
            return cast("SettingValue", fallback_value)

        if setting.is_sensitive:
            logger.debug("⚡ [Settings] Database hit for key: %s (sensitive, not cached)", key)
            return setting.get_typed_value()

        value = setting.get_typed_value()
        cache.set(cache_key, value, timeout=cls.CACHE_TIMEOUT, version=cls.CACHE_VERSION)
        logger.debug("⚡ [Settings] Database hit for key: %s (cached)", key)
        return value

    @classmethod
    def _is_sensitive_key(cls, key: str) -> bool:
        """Catalog-flag sensitivity (name-pattern fallback for unknown ad-hoc keys)"""
        return is_sensitive_key(key)

    @classmethod
    def _coerce_value(cls, key: str, data_type: str, value: Any) -> Any:  # noqa: C901, PLR0911, PLR0912  # Canonical per-type coercion table
        """
        🔬 Coerce raw input to the canonical Python value for data_type.

        Strict on purpose: bool is not an integer, decimals must be finite,
        lists must parse to lists. Raises ValidationError with a clear message.
        """
        if data_type == "boolean":
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in _TRUTHY_STRINGS:
                    return True
                if lowered in _FALSY_STRINGS:
                    return False
            raise ValidationError(_("%(key)s: value must be a boolean") % {"key": key})
        if data_type == "integer":
            if isinstance(value, bool):
                raise ValidationError(_("%(key)s: value must be an integer, not a boolean") % {"key": key})
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value.strip())
                except ValueError as e:
                    raise ValidationError(_("%(key)s: value must be an integer") % {"key": key}) from e
            raise ValidationError(_("%(key)s: value must be an integer") % {"key": key})
        if data_type == "decimal":
            if isinstance(value, bool):
                raise ValidationError(_("%(key)s: value must be a decimal number") % {"key": key})
            try:
                decimal_value = Decimal(str(value).strip())
            except decimal.InvalidOperation as e:
                raise ValidationError(_("%(key)s: value must be a decimal number") % {"key": key}) from e
            if not decimal_value.is_finite():
                raise ValidationError(_("%(key)s: decimal value must be finite") % {"key": key})
            return decimal_value
        if data_type in ("list", "json"):
            parsed = _safe_json_loads(value) if isinstance(value, str) else value
            if data_type == "list" and not isinstance(parsed, list):
                raise ValidationError(_("%(key)s: value must be a JSON list") % {"key": key})
            return parsed
        # string
        if not isinstance(value, str):
            raise ValidationError(_("%(key)s: value must be a string") % {"key": key})
        return value

    @classmethod
    def _validation_rules_for(cls, setting: SystemSetting) -> dict[str, Any]:
        """Catalog-owned validation rules (the model's validation_rules field is retired)"""
        return validation_rules_for_key(setting.key)

    @classmethod
    def _apply_rules(cls, key: str, rules: dict[str, Any], value: Any) -> None:
        """📏 Enforce min/max/choices/pattern rules against a coerced value"""
        if not rules:
            return
        minimum = rules.get("min")
        if minimum is not None and isinstance(value, int | Decimal) and value < Decimal(str(minimum)):
            raise ValidationError(_("%(key)s: value must be at least %(min)s") % {"key": key, "min": minimum})
        maximum = rules.get("max")
        if maximum is not None and isinstance(value, int | Decimal) and value > Decimal(str(maximum)):
            raise ValidationError(_("%(key)s: value must be at most %(max)s") % {"key": key, "max": maximum})
        choices = rules.get("choices")
        if choices is not None and value not in choices:
            raise ValidationError(
                _("%(key)s: value must be one of %(choices)s") % {"key": key, "choices": ", ".join(map(str, choices))}
            )
        pattern = rules.get("pattern")
        if pattern is not None and isinstance(value, str) and re.fullmatch(pattern, value) is None:
            raise ValidationError(_("%(key)s: value does not match the required pattern") % {"key": key})

    @classmethod
    def _validation_error(cls, key: str, exc: ValidationError) -> SettingValidationError:
        """Convert a Django ValidationError into the service error dataclass"""
        message = str(exc.message_dict) if hasattr(exc, "message_dict") else "; ".join(exc.messages)
        return SettingValidationError(key=key, field="value", message=message, code="validation_error")

    @classmethod
    def _write_setting_locked(  # noqa: PLR0913  # Keyword-only write context (actor, reason, change set)
        cls,
        key: str,
        value: Any,
        *,
        user_id: int | None = None,
        reason: str | None = None,
        change_set_id: str | None = None,
        require_absent_on_create: bool = False,
    ) -> Result[SystemSetting, SettingValidationError]:
        """
        🔒 Write one setting under row lock. The caller owns the enclosing transaction.

        No retry decorator and no broad exception handling here — callers decide
        retry and rollback policy. Creation happens inside a savepoint so a lost
        create race cannot poison the caller's transaction.
        """
        try:
            setting = SystemSetting.objects.select_for_update(of=("self",)).get(key=key)
        except SystemSetting.DoesNotExist:
            definition = CATALOG_BY_KEY.get(key)
            data_type = definition.data_type if definition else cls._infer_data_type(value)
            try:
                coerced = cls._coerce_value(key, data_type, value)
            except ValidationError as e:
                return Err(cls._validation_error(key, e))
            try:
                with transaction.atomic():
                    setting = SystemSetting(
                        key=key,
                        name=cls._generate_name_from_key(key),
                        description=f"System setting: {key}",
                        category=key.split(".", maxsplit=1)[0] if "." in key else "system",
                        data_type=data_type,
                        value=cls._prepare_value_for_json(coerced, data_type),
                        default_value=cls._prepare_value_for_json(cls.DEFAULT_SETTINGS.get(key, coerced), data_type),
                        # Stamp sensitivity BEFORE the first save so the initial write
                        # is encrypted and never enters the cache as a plain value.
                        is_sensitive=cls._is_sensitive_key(key),
                    )
                    setting._audit_context = {
                        "user_id": user_id,
                        "reason": reason,
                        "change_set_id": change_set_id,
                        "old_value": None,
                        "new_value": "(hidden)" if setting.is_sensitive else str(coerced),
                    }
                    setting.save()
            except IntegrityError:
                if require_absent_on_create:
                    return Err(
                        SettingValidationError(
                            key=key,
                            field="baseline",
                            message="Setting was created concurrently",
                            code="create_conflict",
                        )
                    )
                setting = SystemSetting.objects.select_for_update(of=("self",)).get(key=key)
            else:
                cls._log_setting_write(setting, user_id=user_id, reason=reason)
                return Ok(setting)

        # str() forces lazy translation proxies (boolean displays are gettext-lazy) into
        # real strings — raw proxies fail JSON serialization at the audit INSERT.
        old_display = str(setting.get_display_value())
        try:
            coerced = cls._coerce_value(key, setting.data_type, value)
            cls._apply_rules(key, cls._validation_rules_for(setting), coerced)
        except ValidationError as e:
            return Err(cls._validation_error(key, e))

        setting.value = cls._prepare_value_for_json(coerced, setting.data_type)
        setting._audit_context = {
            "user_id": user_id,
            "reason": reason,
            "change_set_id": change_set_id,
            "old_value": old_display,
            "new_value": str(setting.get_display_value()),
        }
        try:
            setting.full_clean()
        except ValidationError as e:
            return Err(cls._validation_error(key, e))
        setting.save(update_fields=["value", "updated_at"])
        cls._log_setting_write(setting, user_id=user_id, reason=reason)
        return Ok(setting)

    @classmethod
    def _log_setting_write(cls, setting: SystemSetting, *, user_id: int | None, reason: str | None) -> None:
        """Log a settings write with sensitive values masked"""
        logger.info(
            "✅ [Settings] Updated setting %s to %s by user %s: %s",
            setting.key,
            setting.get_display_value(),
            user_id or "system",
            reason or "no reason provided",
        )

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
            return int(value)  # type: ignore[arg-type]
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
        try:
            return cls._write_setting_locked(key, value, user_id=user_id, reason=reason)
        except Exception as e:
            logger.error("🔥 [Settings] Unexpected error updating %s: %s", key, str(e))
            return Err(
                SettingValidationError(key=key, field="system", message=f"Unexpected error: {e!s}", code="system_error")
            )

    @classmethod
    @monitor_performance()
    def apply_change_set(  # noqa: C901, PLR0912  # Validation, locking, and write phases in one auditable unit
        cls,
        changes: dict[str, Any],
        baselines: dict[str, str | None],
        user_id: int | None = None,
        reason: str | None = None,
    ) -> Result[ChangeSetOutcome, ChangeSetError]:
        """
        📦 Apply a set of non-sensitive setting changes atomically.

        All-or-nothing: static validation first, then all target rows are locked
        in deterministic key order, baselines are compared under lock (verbatim
        ISO-string comparison against updated_at), and only then are writes made.
        Any failure rolls the whole set back. Sensitive keys are rejected —
        secrets change only through the dedicated credential endpoints.

        Baselines: the server-rendered `updated_at.isoformat()` per key, or None
        when the form was rendered without a database row for that key.
        """
        if not changes:
            return Err(ChangeSetError(code="empty"))

        errors: list[SettingValidationError] = []
        for key, value in changes.items():
            if key not in cls.DEFAULT_SETTINGS:
                errors.append(
                    SettingValidationError(key=key, field="key", message="Unknown setting key", code="unknown_key")
                )
                continue
            if cls._is_sensitive_key(key):
                errors.append(
                    SettingValidationError(
                        key=key,
                        field="key",
                        message="Sensitive settings change only through the credential endpoints",
                        code="sensitive_key",
                    )
                )
                continue
            try:
                cls._coerce_value(key, CATALOG_BY_KEY[key].data_type, value)
            except ValidationError as e:
                errors.append(cls._validation_error(key, e))
        if errors:
            return Err(ChangeSetError(code="validation", errors=errors))

        change_set_id = str(uuid.uuid4())
        applied: dict[str, SystemSetting] = {}
        conflicts: list[ChangeSetConflict] = []
        with transaction.atomic():
            sorted_keys = sorted(changes)
            locked = {
                setting.key: setting
                for setting in SystemSetting.objects.select_for_update(of=("self",))
                .filter(key__in=sorted_keys)
                .order_by("key")
            }
            for key in sorted_keys:
                row = locked.get(key)
                baseline = baselines.get(key)
                if row is None:
                    if baseline is not None:
                        conflicts.append(ChangeSetConflict(key=key, server_updated_at=None))
                elif row.is_sensitive:
                    errors.append(
                        SettingValidationError(
                            key=key,
                            field="key",
                            message="Sensitive settings change only through the credential endpoints",
                            code="sensitive_key",
                        )
                    )
                elif baseline is None or baseline != row.updated_at.isoformat():
                    conflicts.append(ChangeSetConflict(key=key, server_updated_at=row.updated_at.isoformat()))
            if errors or conflicts:
                transaction.set_rollback(True)
                return Err(
                    ChangeSetError(code="conflict" if conflicts else "validation", errors=errors, conflicts=conflicts)
                )

            for key in sorted_keys:
                result = cls._write_setting_locked(
                    key,
                    changes[key],
                    user_id=user_id,
                    reason=reason,
                    change_set_id=change_set_id,
                    require_absent_on_create=key not in locked,
                )
                match result:
                    case Ok(setting):
                        applied[key] = setting
                    case Err(error):
                        transaction.set_rollback(True)
                        if error.code == "create_conflict":
                            return Err(
                                ChangeSetError(
                                    code="conflict",
                                    conflicts=[ChangeSetConflict(key=key, server_updated_at=None)],
                                )
                            )
                        return Err(ChangeSetError(code="validation", errors=[error]))

        logger.info(
            "✅ [Settings] Applied change set %s (%d settings) by user %s",
            change_set_id,
            len(applied),
            user_id or "system",
        )
        return Ok(ChangeSetOutcome(change_set_id=change_set_id, settings=applied))

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

            match result:
                case Ok(value):
                    updated_settings.append(value)
                case Err(error):
                    errors.append(error)

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

        return cls.update_setting(key=key, value=default_value, user_id=user_id, reason="Reset to default value")

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
        if not (SETTING_KEY_MIN_PARTS <= len(parts) <= SETTING_KEY_MAX_PARTS):
            return False

        category = parts[0]
        return category.isalnum() and all(part.replace("_", "").replace("-", "").isalnum() for part in parts[1:])

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
        raise ValidationError(_("JSON too large - exceeds 1MB limit"))

    # Parse with depth checking
    def parse_with_depth_check(obj: Any, current_depth: int = 0) -> Any:
        if current_depth > MAX_JSON_DEPTH:
            raise ValidationError(_("JSON too deeply nested"))

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
        raise ValidationError(_("Invalid JSON format: %(error)s") % {"error": str(e)}) from e
    except RecursionError as e:
        raise ValidationError(_("JSON nesting too deep - exceeds %(depth)s levels") % {"depth": MAX_JSON_DEPTH}) from e
