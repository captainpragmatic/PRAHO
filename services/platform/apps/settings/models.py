"""
System Settings models for PRAHO Platform
Centralized configuration management with type validation and caching.
"""

from __future__ import annotations

import decimal
import json
from decimal import Decimal
from typing import Any, ClassVar, Literal, cast

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# Valid data types for system settings
SettingDataType = Literal["string", "integer", "boolean", "decimal", "list", "json"]

# Valid setting categories
SettingCategoryType = Literal[
    "billing", "users", "domains", "provisioning", "security", "notifications", "integrations", "system"
]


class SettingCategory(models.Model):
    """🏷️ Setting category for organizing system configurations"""

    key = models.CharField(
        _("Key"), max_length=50, unique=True, help_text=_('Unique category identifier (e.g., "billing")')
    )

    name = models.CharField(_("Name"), max_length=100, help_text=_("Human-readable category name"))

    description = models.TextField(_("Description"), blank=True, help_text=_("Category description for staff"))

    display_order = models.PositiveIntegerField(
        _("Display Order"), default=0, help_text=_("Order in which to display this category")
    )

    is_active = models.BooleanField(
        _("Is Active"), default=True, help_text=_("Whether this category is currently active")
    )

    created_at = models.DateTimeField(
        _("Created At"), default=timezone.now, help_text=_("When this category was created")
    )

    updated_at = models.DateTimeField(
        _("Updated At"), auto_now=True, help_text=_("When this category was last updated")
    )

    class Meta:
        verbose_name = _("Setting Category")
        verbose_name_plural = _("Setting Categories")
        ordering: ClassVar = ["display_order", "name"]
        indexes: ClassVar = [
            models.Index(fields=["key"]),
            models.Index(fields=["display_order"]),
        ]

    def __str__(self) -> str:
        return f"🏷️ {self.name}"

    def clean(self) -> None:
        """Validate category data"""
        super().clean()

        # Normalize key to lowercase
        if self.key:
            self.key = self.key.lower().replace(" ", "_")


class SystemSetting(models.Model):
    """⚙️ System setting with type validation and caching support"""

    # Data type choices for validation
    DATA_TYPE_CHOICES: ClassVar[list[tuple[str, str]]] = [
        ("string", cast(str, _("String"))),
        ("integer", cast(str, _("Integer"))),
        ("boolean", cast(str, _("Boolean"))),
        ("decimal", cast(str, _("Decimal"))),
        ("list", cast(str, _("List"))),
        ("json", cast(str, _("JSON"))),
    ]

    key = models.CharField(
        _("Key"),
        max_length=100,
        unique=True,
        help_text=_('Unique setting identifier (e.g., "billing.proforma_validity_days")'),
    )

    category = models.CharField(
        _("Category"), max_length=50, default="system", help_text=_("Setting category for organization")
    )

    name = models.CharField(_("Name"), max_length=200, help_text=_("Human-readable setting name"))

    description = models.TextField(_("Description"), help_text=_("Detailed description of what this setting controls"))

    data_type = models.CharField(
        _("Data Type"),
        max_length=20,
        choices=DATA_TYPE_CHOICES,
        default="string",
        help_text=_("Type of data this setting stores"),
    )

    value = models.JSONField(_("Value"), help_text=_("Current setting value"))

    default_value = models.JSONField(
        _("Default Value"), help_text=_("Default value to use if setting is not configured")
    )

    is_required = models.BooleanField(
        _("Is Required"), default=False, help_text=_("Whether this setting must have a value")
    )

    is_sensitive = models.BooleanField(
        _("Is Sensitive"), default=False, help_text=_("Whether this setting contains sensitive data")
    )

    is_active = models.BooleanField(
        _("Is Active"), default=True, help_text=_("Whether this setting is currently active")
    )

    is_public = models.BooleanField(
        _("Is Public"), default=False, help_text=_("Whether this setting can be accessed publicly")
    )

    requires_restart = models.BooleanField(
        _("Requires Restart"), default=False, help_text=_("Whether changing this setting requires application restart")
    )

    validation_rules = models.JSONField(
        _("Validation Rules"),
        default=dict,
        blank=True,
        help_text=_("JSON object with validation rules (min, max, pattern, etc.)"),
    )

    help_text = models.TextField(_("Help Text"), blank=True, help_text=_("Additional help text for staff users"))

    created_at = models.DateTimeField(
        _("Created At"), default=timezone.now, help_text=_("When this setting was created")
    )

    updated_at = models.DateTimeField(_("Updated At"), auto_now=True, help_text=_("When this setting was last updated"))

    class Meta:
        verbose_name = _("System Setting")
        verbose_name_plural = _("System Settings")
        ordering: ClassVar = ["category", "key"]
        indexes: ClassVar = [
            models.Index(fields=["key"]),
            models.Index(fields=["category"]),
            models.Index(fields=["updated_at"]),
        ]

    def __str__(self) -> str:
        return f"⚙️ {self.key}: {self.get_display_value()}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save setting with automatic encryption for sensitive values"""
        # Handle encryption for sensitive settings
        if self.is_sensitive and self.value is not None:
            from .encryption import SettingsEncryption  # noqa: PLC0415

            encryption = SettingsEncryption()
            # Only encrypt if not already encrypted
            if not encryption.is_encrypted(str(self.value)):
                self.value = encryption.encrypt_value(str(self.value))

        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validate setting data"""
        super().clean()

        # Validate key format (category.setting_name)
        if self.key and "." not in self.key:
            raise ValidationError({"key": _('Setting key must be in format "category.setting_name"')})

        # Validate data type and value
        self._validate_value(self.value, "value")
        self._validate_value(self.default_value, "default_value")

        # Ensure required settings have values
        if self.is_required and self.value is None:
            raise ValidationError({"value": _("Required settings must have a value")})

    def _validate_value(  # noqa: C901, PLR0912 - Setting validation requires checking all data types
        self, value: Any, field_name: str
    ) -> None:
        """Validate value against data type"""
        if value is None:
            return

        try:
            if self.data_type == "string":
                if not isinstance(value, str):
                    raise ValidationError({field_name: _("Value must be a string")})
            elif self.data_type == "integer":
                if not isinstance(value, int):
                    int(value)  # Try to convert
            elif self.data_type == "boolean":
                if not isinstance(value, bool):
                    raise ValidationError({field_name: _("Value must be a boolean")})
            elif self.data_type == "decimal":
                if not isinstance(value, int | float | str | Decimal):
                    raise ValidationError({field_name: _("Value must be a decimal number")})
                Decimal(str(value))  # Validate decimal conversion
            elif self.data_type == "list":
                if not isinstance(value, list):
                    raise ValidationError({field_name: _("Value must be a list")})
            elif self.data_type == "json":
                # JSON is already validated by JSONField
                pass
        except (ValueError, TypeError, decimal.InvalidOperation) as e:
            raise ValidationError(
                {
                    field_name: _('Invalid value for data type "%(type)s": %(error)s')
                    % {"type": self.data_type, "error": str(e)}
                }
            ) from e

    def get_typed_value(self) -> str | int | bool | Decimal | list[Any] | dict[str, Any] | None:
        """Get the setting value converted to its proper Python type"""
        if self.value is None:
            return self.get_typed_default_value()

        # Handle decryption for sensitive settings
        raw_value = self.value
        if self.is_sensitive and raw_value is not None:
            from .encryption import SettingsEncryption  # noqa: PLC0415

            encryption = SettingsEncryption()
            if encryption.is_encrypted(str(raw_value)):
                raw_value = encryption.decrypt_value(str(raw_value))

        if self.data_type == "decimal" and raw_value is not None:
            return Decimal(str(raw_value))

        return cast("str | int | bool | Decimal | list[Any] | dict[str, Any] | None", raw_value)

    def get_typed_default_value(self) -> str | int | bool | Decimal | list[Any] | dict[str, Any] | None:
        """Get the default value converted to its proper Python type"""
        if self.default_value is None:
            return None

        if self.data_type == "decimal" and self.default_value is not None:
            return Decimal(str(self.default_value))

        return cast("str | int | bool | Decimal | list[Any] | dict[str, Any] | None", self.default_value)

    def get_display_value(self) -> str:
        """Get a human-readable representation of the current value"""
        typed_value = self.get_typed_value()

        if typed_value is None:
            return cast(str, _("(not set)"))

        if self.is_sensitive:
            return cast(str, _("(hidden)"))

        if self.data_type == "boolean":
            return cast(str, _("Yes") if typed_value else _("No"))
        elif self.data_type in ("list", "json"):
            try:
                return json.dumps(typed_value, indent=2, ensure_ascii=False)
            except (TypeError, ValueError):
                return str(typed_value)
        else:
            return str(typed_value)

    @property
    def category_display(self) -> str:
        """Get human-readable category name"""
        # Simple capitalization of category name since CATEGORY_CHOICES doesn't exist
        return self.category.replace("_", " ").title()

    def reset_to_default(self) -> None:
        """Reset setting to its default value"""
        self.value = self.default_value
        self.save(update_fields=["value", "updated_at"])

    @classmethod
    def get_by_key(cls, key: str) -> SystemSetting | None:
        """Get setting by key, return None if not found"""
        try:
            return cls.objects.get(key=key)
        except cls.DoesNotExist:
            return None

    @classmethod
    def get_public_settings(cls) -> models.QuerySet[SystemSetting]:
        """Get all public settings that can be accessed without authentication"""
        return cls.objects.filter(is_active=True, is_public=True)

    @classmethod
    def get_value_by_key(cls, key: str, default: Any = None) -> Any:
        """Get setting value by key, return default if not found"""
        setting = cls.get_by_key(key)
        if setting is None:
            return default
        return setting.get_typed_value()
