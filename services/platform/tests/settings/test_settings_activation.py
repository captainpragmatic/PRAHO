"""N4 activation reconciliation is atomic, durable, and independent of row provenance."""

from __future__ import annotations

from dataclasses import replace
from io import StringIO
from unittest.mock import patch

from django.apps import apps
from django.core.cache import cache
from django.core.management import call_command
from django.db.models import JSONField, Value
from django.test import TestCase, override_settings

from apps.audit.models import AuditAlert
from apps.settings.catalog import CATALOG_BY_KEY, SettingDef
from apps.settings.management.commands import setup_default_settings as sync
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService

KEY = "notifications.max_name_length"
SECOND = "notifications.max_subject_length"


class SettingsActivationTests(TestCase):
    def definition(self, key: str = KEY, default: int = 200) -> SettingDef:
        return replace(CATALOG_BY_KEY[key], default=default)

    def seed(self, value: object, key: str = KEY, default: int = 100) -> SystemSetting:
        definition = self.definition(key, default)
        row = SystemSetting.objects.create(
            key=key, value=0 if value is None else value, **sync._row_defaults(definition)
        )
        if value is None:
            SystemSetting.objects.filter(pk=row.pk).update(value=Value(None, output_field=JSONField()))
            row.refresh_from_db()
        return row

    def run_sync(
        self,
        definitions: tuple[SettingDef, ...],
        changes: dict[str, tuple[object, object]],
        retired: frozenset[str] = frozenset(),
        category: str | None = None,
        force: bool = False,
    ) -> str:
        output = StringIO()
        options: dict[str, object] = {"stdout": output, "force": force}
        if category is not None:
            options["category"] = category
        with (
            patch.object(sync, "CATALOG", definitions),
            patch.object(sync, "DEFAULT_VALUE_MIGRATIONS", changes, create=True),
            patch.object(sync, "RETIRED_SETTING_KEYS", retired, create=True),
            self.captureOnCommitCallbacks(execute=True),
        ):
            call_command("setup_default_settings", **options)
        return output.getvalue()

    def test_metadata_only_sync_does_not_hide_an_old_default(self) -> None:
        row = self.seed(100)
        previous_timestamp = row.updated_at
        SystemSetting.objects.filter(pk=row.pk).update(name="stale metadata")
        self.run_sync((self.definition(default=100),), {})
        row.refresh_from_db()
        self.assertGreater(row.updated_at, previous_timestamp)
        output = self.run_sync((self.definition(),), {KEY: (100, 200)})
        row.refresh_from_db()
        self.assertEqual(row.value, 200)
        self.assertIn(f"{KEY}: 100 → 200", output)
        self.assertEqual(row.default_value, 200)
        self.assertFalse(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").exists())

    @override_settings(
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "wp18-activation"}}
    )
    def test_explicit_old_default_override_is_rewritten_only_once(self) -> None:
        row = self.seed(100)
        row._audit_context = {"reason": "Explicit staff choice"}
        row.save(update_fields=["value", "updated_at"])
        cache_key = SettingsService._get_cache_key(KEY)
        cache.set(cache_key, 100, version=SettingsService.CACHE_VERSION)
        self.run_sync((self.definition(),), {KEY: (100, 200)})
        row.refresh_from_db()
        self.assertEqual(row.value, 200)
        self.assertIsNone(cache.get(cache_key, version=SettingsService.CACHE_VERSION))
        self.assertEqual(SettingsService.get_integer_setting(KEY, 0), 200)
        row.value = 100
        row.save(update_fields=["value", "updated_at"])
        self.run_sync((self.definition(),), {KEY: (100, 200)})
        row.refresh_from_db()
        self.assertEqual(row.value, 100)
        output = self.run_sync((self.definition(), self.definition(SECOND, 300)), {KEY: (100, 200), SECOND: (200, 300)})
        self.assertIn(f"Created: {SECOND}", output)
        self.assertEqual(SystemSetting.objects.get(key=SECOND).value, 300)
        receipt = apps.get_model("settings", "SettingActivation").objects.get(key=KEY)
        self.assertEqual(receipt.version, "wp18-v1")
        self.assertIsNotNone(receipt.completed_at)

    def test_distinct_values_are_preserved_and_listed_in_one_warning(self) -> None:
        first = self.seed(250)
        second = self.seed(350, SECOND, 200)
        changes = {KEY: (100, 200), SECOND: (200, 300)}
        definitions = (self.definition(), self.definition(SECOND, 300))
        output = self.run_sync(definitions, changes)
        alerts = AuditAlert.objects.filter(metadata__activation_version="wp18-v1")
        self.assertEqual(alerts.count(), 1)
        alert = alerts.get()
        self.assertEqual((alert.alert_type, alert.severity, alert.status), ("data_integrity", "warning", "active"))
        self.assertEqual(alert.evidence["retained_values"], {KEY: 250, SECOND: 350})
        self.assertEqual(alert.evidence["previous_enforced_values"], {KEY: 200, SECOND: 300})
        for row, expected in ((first, 250), (second, 350)):
            row.refresh_from_db()
            self.assertEqual(row.value, expected)
            self.assertIn(row.key, output)
            self.assertIn(row.key, alert.description)
        self.assertIn("stored value now takes effect", alert.description)
        self.run_sync(definitions, changes)
        self.assertEqual(alerts.count(), 1)

    def test_retired_row_is_deleted_and_category_filter_is_respected(self) -> None:
        row = self.seed(123)
        other = self.seed(321, SECOND)
        SystemSetting.objects.filter(pk=other.pk).update(category="other")
        output = self.run_sync((), {}, frozenset({KEY, SECOND}), category=self.definition().group)
        self.assertFalse(SystemSetting.objects.filter(pk=row.pk).exists())
        self.assertIn(f"Deleted retired setting: {KEY}", output)
        self.assertTrue(SystemSetting.objects.filter(pk=other.pk).exists())

    def test_alert_failure_rolls_back_rewrites_receipts_and_retirement(self) -> None:
        first = self.seed(100)
        second = self.seed(350, SECOND, 200)
        retired = SystemSetting.objects.create(
            key="foundation.retired", name="Retired", value=1, default_value=1, category="notifications"
        )
        with (
            patch.object(AuditAlert.objects, "create", side_effect=RuntimeError("alert unavailable")),
            self.assertRaisesMessage(RuntimeError, "alert unavailable"),
        ):
            self.run_sync(
                (self.definition(), self.definition(SECOND, 300)),
                {KEY: (100, 200), SECOND: (200, 300)},
                frozenset({retired.key}),
            )
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual((first.value, first.default_value, second.value, second.default_value), (100, 100, 350, 200))
        self.assertTrue(SystemSetting.objects.filter(pk=retired.pk).exists())
        self.assertFalse(apps.get_model("settings", "SettingActivation").objects.exists())

    def test_null_and_malformed_values_are_kept_without_claiming_they_take_effect(self) -> None:
        first = self.seed(None)
        second = self.seed("invalid-integer", SECOND, 200)
        output = self.run_sync((self.definition(), self.definition(SECOND, 300)), {KEY: (100, 200), SECOND: (200, 300)})
        self.assertIn(f"Fallback-only value retained: {SECOND}", output)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNone(first.value)
        self.assertEqual(first.get_typed_value(), 200)
        self.assertEqual(second.value, "invalid-integer")
        self.assertEqual(second.default_value, 300)
        self.assertFalse(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").exists())
