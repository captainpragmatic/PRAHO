"""
Sync catalog metadata and perform explicitly registered, one-time setting activations.

Ordinary sync preserves values except old defaults in the activation manifest.
--force explicitly resets values. Retired rows are deleted within the same transaction.
"""

from __future__ import annotations

import logging

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.settings.catalog import CATALOG, SettingDef
from apps.settings.models import SettingActivation, SystemSetting

logger = logging.getLogger(__name__)

# Later foundation consumers register old catalog default -> previously enforced value here.
# Equal pairs can register an activation whose catalog default does not change.
DEFAULT_VALUE_MIGRATIONS: dict[str, tuple[object, object]] = {
    "audit.compliant_score_threshold": (90, 90),
    "audit.high_complexity_filter_threshold": (5, 5),
    "audit.max_files_displayed": (5, 5),
    "audit.max_violations_displayed": (10, 10),
    "audit.partial_score_threshold": (70, 70),
    "audit.webhook_healthy_response_threshold": (300, 300),
    "audit.webhook_max_retry_threshold": (5, 5),
    "audit.webhook_suspicious_retry_threshold": (3, 3),
    "billing.event_grace_period_hours": (24, 24),
    "billing.metering_task_timeout": (300, 300),
    "billing.subscription_grace_period_days": (7, 7),
    "common.cache_timeout_medium": (300, 300),
    "common.cache_timeout_short": (60, 60),
    "common.default_orphans": (3, 3),
    "common.max_header_json_length": (1000, 1000),
    "common.max_summarized_args": (3, 3),
    "common.proximity_line_threshold": (5, 5),
    "common.query_warning_threshold": (10, 10),
    "common.sql_display_limit": (200, 200),
    "common.value_summary_limit": (50, 50),
}
RETIRED_SETTING_KEYS: frozenset[str] = frozenset(
    {
        "billing.alert_cooldown_hours",
        "billing.max_payment_retry_attempts",
        "billing.task_max_retries",
        "billing.task_retry_delay_seconds",
        "common.cache_timeout_long",
        "common.cache_timeout_very_long",
        "notifications.max_recipients_per_batch",
        "orders.task_soft_time_limit",
        "provisioning.health_check_timeout_seconds",
        "provisioning.long_provisioning_threshold_minutes",
        "provisioning.resource_usage_alert_threshold",
        "provisioning.server_overload_threshold",
        "users.credential_max_age_days",
        "users.credential_rotation_retry_limit",
    }
)
ACTIVATION_VERSION = "wp18-v1"

_METADATA_FIELDS = ("name", "description", "help_text", "data_type", "is_sensitive", "is_required", "category")


def _row_defaults(definition: SettingDef) -> dict[str, object]:
    return {
        "name": definition.label,
        "description": definition.help_text or _("System setting: %(key)s") % {"key": definition.key},
        "help_text": definition.help_text,
        "category": definition.group,
        "data_type": definition.data_type,
        "is_sensitive": definition.sensitive,
        "is_required": bool(definition.validation and definition.validation.get("required")),
        "default_value": definition.default,
    }


def _reconcile(setting: SystemSetting, definition: SettingDef, force: bool, rewrite: bool) -> list[str]:
    defaults = _row_defaults(definition)
    dirty_fields: list[str] = []
    if setting.is_sensitive and not definition.sensitive:
        from apps.common.encryption import decrypt_value, is_encrypted  # noqa: PLC0415  # ADR-0007

        if setting.value is not None and is_encrypted(str(setting.value)):
            setting.value = decrypt_value(str(setting.value))
            dirty_fields.append("value")
    for field_name in _METADATA_FIELDS:
        if getattr(setting, field_name) != defaults[field_name]:
            setattr(setting, field_name, defaults[field_name])
            dirty_fields.append(field_name)
    if setting.default_value != definition.default:
        setting.default_value = definition.default
        dirty_fields.append("default_value")
    if (force or rewrite) and setting.value != definition.default:
        setting.value = definition.default
        dirty_fields.append("value")
    if dirty_fields:
        setting.save(update_fields=[*dict.fromkeys(dirty_fields), "updated_at"])
    return dirty_fields


def _activation_receipt(key: str) -> SettingActivation:
    SettingActivation.objects.get_or_create(key=key, defaults={"version": ACTIVATION_VERSION})
    return SettingActivation.objects.select_for_update().get(key=key)


def _retained_value_is_effective(setting: SystemSetting, definition: SettingDef) -> bool:
    if setting.value is None:
        return False
    validator = SystemSetting(data_type=definition.data_type)
    try:
        validator._validate_value(setting.get_typed_value(), "value")
    except (ValidationError, ValueError, TypeError):
        return False
    return True


def _classify_activation(
    setting: SystemSetting,
    definition: SettingDef,
    transition: tuple[object, object] | None,
    activate: bool,
    messages: list[str],
) -> tuple[bool, bool]:
    if not activate or transition is None:
        return False, False
    if setting.value == transition[0]:
        if setting.value != definition.default:
            messages.append(
                _("  🔄 Rewrote: %(key)s: %(old)s → %(new)s")
                % {"key": definition.key, "old": transition[0], "new": definition.default}
            )
        return True, False
    if _retained_value_is_effective(setting, definition):
        messages.append(_("  ⚠️ Stored value now takes effect: %(key)s") % {"key": definition.key})
        return False, True
    messages.append(_("  ✅ Fallback-only value retained: %(key)s") % {"key": definition.key})
    return False, False


def _activation_alert(retained: dict[str, object], enforced: dict[str, object]) -> None:
    if not retained:
        return
    from apps.audit.models import AuditAlert  # noqa: PLC0415  # ADR-0007

    keys = ", ".join(sorted(retained))
    AuditAlert.objects.create(
        alert_type="data_integrity",
        severity="warning",
        status="active",
        title=_("Settings activation: stored value now takes effect"),
        description=_(
            "The stored value now takes effect for these settings: %(keys)s. "
            "Review the retained configuration; its provenance is unknown."
        )
        % {"keys": keys},
        evidence={"previous_enforced_values": enforced, "retained_values": retained},
        metadata={"activation_version": ACTIVATION_VERSION, "keys": sorted(retained)},
    )
    transaction.on_commit(lambda: logger.warning("⚠️ [Settings] Stored value now takes effect: %s", keys))


def _retire_settings(category_filter: str | None, messages: list[str]) -> None:
    retired = SystemSetting.objects.select_for_update().filter(key__in=RETIRED_SETTING_KEYS).order_by("key")
    if category_filter:
        retired = retired.filter(category=category_filter)
    for setting in retired:
        key = setting.key
        setting.delete()
        messages.append(_("  🗑️ Deleted retired setting: %(key)s") % {"key": key})


class Command(BaseCommand):
    help = _("Create missing settings, reconcile metadata and apply registered one-time activations")

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--force", action="store_true", help=_("Also reset values to catalog defaults"))
        parser.add_argument("--category", type=str, help=_("Only sync settings for a specific group"))

    def handle(self, *args: object, **options: object) -> None:
        force = bool(options.get("force", False))
        category_filter = str(options["category"]) if options.get("category") else None
        messages: list[str] = []
        created = updated = unchanged = 0
        retained: dict[str, object] = {}
        enforced: dict[str, object] = {}

        with transaction.atomic():
            _retire_settings(category_filter, messages)

            for definition in CATALOG:
                if category_filter and definition.group != category_filter:
                    continue
                if definition.key in RETIRED_SETTING_KEYS:
                    raise CommandError(_("Retired setting is still in the catalog: %(key)s") % {"key": definition.key})

                transition = DEFAULT_VALUE_MIGRATIONS.get(definition.key)
                receipt = _activation_receipt(definition.key) if transition is not None else None
                activate = receipt is not None and receipt.completed_at is None
                if transition is not None and transition[1] != definition.default:
                    raise CommandError(
                        _("Activation default disagrees with the catalog: %(key)s") % {"key": definition.key}
                    )

                setting, was_created = SystemSetting.objects.select_for_update().get_or_create(
                    key=definition.key,
                    defaults={**_row_defaults(definition), "value": definition.default},
                )
                rewrite, effective = _classify_activation(
                    setting, definition, transition, activate and not was_created and not force, messages
                )
                if effective:
                    retained[definition.key] = "(hidden)" if definition.sensitive else setting.value
                    enforced[definition.key] = definition.default

                if was_created:
                    created += 1
                    messages.append(_("  ✅ Created: %(key)s") % {"key": definition.key})
                else:
                    dirty_fields = _reconcile(setting, definition, force, rewrite)
                    if dirty_fields:
                        updated += 1
                        messages.append(
                            _("  🔄 Reconciled: %(key)s (%(fields)s)")
                            % {"key": definition.key, "fields": ", ".join(dirty_fields)}
                        )
                    else:
                        unchanged += 1
                if activate and receipt is not None:
                    receipt.completed_at = timezone.now()
                    receipt.save(update_fields=["completed_at"])

            _activation_alert(retained, enforced)

        self.stdout.write(self.style.SUCCESS(_("🚀 Syncing system settings with the catalog...")))
        for message in messages:
            self.stdout.write(message)
        self.stdout.write(self.style.SUCCESS(_("\n📊 Sync summary:")))
        self.stdout.write(_("  • Created: %(count)s") % {"count": created})
        self.stdout.write(_("  • Reconciled: %(count)s") % {"count": updated})
        self.stdout.write(_("  • Unchanged: %(count)s") % {"count": unchanged})
        self.stdout.write(self.style.SUCCESS(_("✅ Settings catalog sync complete!")))
