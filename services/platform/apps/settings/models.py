"""
System Settings models for PRAHO Platform
Centralized configuration management with type validation and caching.
"""

from __future__ import annotations

import decimal
import json
import uuid
from decimal import Decimal
from typing import Any, ClassVar, Literal, cast

from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.db_functions import RandomContextUUID
from apps.common.encryption import ENCRYPTED_PREFIX
from apps.common.model_secrets import (
    decrypt_model_secret,
    encrypt_model_secret,
    seal_model_secret,
    written_fields,
)

# Valid data types for system settings
SettingDataType = Literal["string", "integer", "boolean", "decimal", "list", "json"]

# Valid setting categories


class SystemSetting(models.Model):
    """⚙️ System setting with type validation and caching support"""

    encryption_context_id = models.UUIDField(
        default=uuid.uuid4, db_default=RandomContextUUID(), unique=True, editable=False
    )

    # Transient audit context attached by SettingsService writes just before save;
    # consumed (and cleared) by the post_save signal to attribute the audit event.
    _audit_context: dict[str, Any] | None = None

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

    # blank=True: an empty value is legitimate (cleared credentials, empty defaults)
    value = models.JSONField(_("Value"), blank=True, help_text=_("Current setting value"))

    default_value = models.JSONField(
        _("Default Value"), blank=True, help_text=_("Default value to use if setting is not configured")
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

    requires_restart = models.BooleanField(
        _("Requires Restart"), default=False, help_text=_("Whether changing this setting requires application restart")
    )

    help_text = models.TextField(_("Help Text"), blank=True, help_text=_("Additional help text for staff users"))

    created_at = models.DateTimeField(
        _("Created At"), default=timezone.now, help_text=_("When this setting was created")
    )

    updated_at = models.DateTimeField(_("Updated At"), auto_now=True, help_text=_("When this setting was last updated"))
    revision = models.PositiveBigIntegerField(default=1, editable=False)

    class Meta:
        db_table = "setting_entries"
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

    @transaction.atomic
    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save setting with automatic encryption for sensitive values"""
        update_fields = kwargs.get("update_fields")
        if self.key == "billing.default_currency" and (update_fields is None or "value" in update_fields):
            from apps.billing.currency_policy import prepare_currency_setting_save  # noqa: PLC0415  # ADR-0007

            prepare_currency_setting_save(self)
            if update_fields is not None:
                kwargs["update_fields"] = {*update_fields, "revision"}
        sync_whois_price = self.key == "domains.whois_privacy_price_cents" and (
            update_fields is None or "value" in update_fields
        )
        if sync_whois_price:
            from apps.billing.currency_policy import get_selling_currency_policy  # noqa: PLC0415  # ADR-0007

            get_selling_currency_policy(lock=True)
        # Seal sensitive values for this row and field; an empty value means "cleared / not configured" and
        # is stored plain. Only the fields being written are sealed, and a save that writes is_sensitive
        # writes both values with it: a setting that becomes sensitive never keeps plaintext on disk.
        if self.is_sensitive:
            self._seal_sensitive_values(kwargs)

        super().save(*args, **kwargs)
        if sync_whois_price:
            from apps.billing.currency_service import default_selling_currency  # noqa: PLC0415  # ADR-0007
            from apps.domains.models import TLDRetailPrice  # noqa: PLC0415  # ADR-0007

            for price in TLDRetailPrice.objects.filter(currency_id=default_selling_currency()):
                price.whois_privacy_price_cents = int(self.value)
                price.save(update_fields=["whois_privacy_price_cents", "updated_at"])

    def _seal_sensitive_values(self, kwargs: dict[str, Any]) -> None:
        update_fields, written = written_fields(kwargs, ("value", "default_value"))
        if update_fields is not None and "is_sensitive" in update_fields:
            written = ["value", "default_value"]
            update_fields.extend(field for field in written if field not in update_fields)
        sealed: dict[str, str] = {}
        for field in written:  # Every field is sealed before any changes: a refusal leaves the row as it was
            value = getattr(self, field)
            if value is None or value == "":
                continue
            if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
                sealed[field] = seal_model_secret(self, field, value)  # Kept only if it is this field's
            else:
                payload = str(value) if self.data_type == "string" else json.dumps(value, default=str)
                sealed[field] = encrypt_model_secret(self, field, payload)
        for field, value in sealed.items():
            setattr(self, field, value)

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

    def _validate_value(  # noqa: C901, PLR0912  # Complexity: multi-step business logic
        self, value: Any, field_name: str
    ) -> None:  # Complexity: multi-step workflow  # Complexity: multi-step business logic
        """Validate value against data type"""
        if value is None:
            return

        if self.is_sensitive and isinstance(value, str) and value.startswith("aes:"):
            value = self._read_sensitive_value(field_name, value)

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

    def _read_sensitive_value(self, field: str, value: Any) -> Any:
        decrypted = decrypt_model_secret(self, field, str(value))
        return decrypted if self.data_type == "string" or decrypted == "" else json.loads(decrypted)

    def get_typed_value(self) -> str | int | bool | Decimal | list[Any] | dict[str, Any] | None:
        """Get the setting value converted to its proper Python type"""
        if self.value is None:
            return self.get_typed_default_value()

        # Handle decryption for sensitive settings
        raw_value = self.value
        if self.is_sensitive and raw_value is not None:
            raw_value = self._read_sensitive_value("value", raw_value)

        if self.data_type == "decimal" and raw_value is not None:
            return Decimal(str(raw_value))

        return cast("str | int | bool | Decimal | list[Any] | dict[str, Any] | None", raw_value)

    def get_typed_default_value(self) -> str | int | bool | Decimal | list[Any] | dict[str, Any] | None:
        """Get the default value converted to its proper Python type"""
        if self.default_value is None:
            return None
        raw_value = self.default_value
        if self.is_sensitive:
            raw_value = self._read_sensitive_value("default_value", raw_value)
        if self.data_type == "decimal":
            return Decimal(str(raw_value))
        return cast("str | int | bool | Decimal | list[Any] | dict[str, Any] | None", raw_value)

    def get_display_value(self) -> str:
        """Get a human-readable representation of the current value"""
        if self.is_sensitive:
            return cast(str, _("(hidden)"))
        typed_value = self.get_typed_value()

        if typed_value is None:
            return cast(str, _("(not set)"))

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
    def get_value_by_key(cls, key: str, default: Any = None) -> Any:
        """Get setting value by key, return default if not found"""
        setting = cls.get_by_key(key)
        if setting is None:
            return default
        return setting.get_typed_value()


class SettingActivation(models.Model):
    """Durable per-key receipt; catalog sync timestamps are not activation provenance."""

    key = models.CharField(max_length=100, primary_key=True)
    version = models.CharField(max_length=40)
    created_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "setting_activations"
        verbose_name = _("Setting activation")
        verbose_name_plural = _("Setting activations")
