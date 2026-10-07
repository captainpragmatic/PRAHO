"""The commercial batch registers every activation and preserves enforced defaults."""

from dataclasses import replace
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase

from apps.audit.models import AuditAlert
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.management.commands import setup_default_settings as sync
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import SettingsService

TRANSITIONS = {
    "notifications.max_name_length": (100, 200),
    "notifications.max_subject_length": (200, 200),
    "notifications.max_template_size": (102400, 100000),
    "products.max_json_content_size": (102400, 10000),
    "products.max_price_cents": (10000000000, 100000000),
    "promotions.max_code_generation_attempts": (100, 100),
}
CONFIGURED = {
    "notifications.max_name_length": 10,
    "notifications.max_subject_length": 10,
    "notifications.max_template_size": 10,
    "products.max_json_content_size": 10,
    "products.max_price_cents": 1000,
    "promotions.max_code_generation_attempts": 1,
}


class CommercialSettingsActivationTests(TestCase):
    def run_sync(self) -> str:
        output = StringIO()
        definitions = tuple(CATALOG_BY_KEY[key] for key in TRANSITIONS)
        with patch.object(sync, "CATALOG", definitions):
            call_command("setup_default_settings", stdout=output)
        return output.getvalue()

    def test_missing_rows_use_enforced_defaults_and_receive_activation_receipts(self) -> None:
        self.run_sync()
        self.assertEqual(
            dict(SystemSetting.objects.filter(key__in=TRANSITIONS).values_list("key", "value")),
            {key: new for key, (_old, new) in TRANSITIONS.items()},
        )
        self.assertEqual(SettingActivation.objects.filter(key__in=TRANSITIONS, completed_at__isnull=False).count(), 6)
        self.assertFalse(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").exists())

    def test_old_defaults_are_rewritten_after_metadata_sync_only_on_first_activation(self) -> None:
        for key, (old, new) in TRANSITIONS.items():
            result = SettingsService.update_setting(key, old, reason="Explicit staff choice before activation")
            self.assertTrue(result.is_ok(), result)
            row = SystemSetting.objects.get(key=key)
            # Ordinary metadata reconciliation must not conceal the historical raw value.
            sync._reconcile(row, replace(CATALOG_BY_KEY[key], default=new), force=False, rewrite=False)
            self.assertEqual(row.value, old)
        output = self.run_sync()
        self.assertEqual(
            dict(SystemSetting.objects.filter(key__in=TRANSITIONS).values_list("key", "value")),
            {key: new for key, (_old, new) in TRANSITIONS.items()},
        )
        for key, (old, new) in TRANSITIONS.items():
            if old != new:
                self.assertIn(f"{key}: {old} → {new}", output)
            result = SettingsService.update_setting(key, old, reason="New choice after activation")
            self.assertTrue(result.is_ok(), result)
        self.run_sync()
        self.assertEqual(
            dict(SystemSetting.objects.filter(key__in=TRANSITIONS).values_list("key", "value")),
            {key: old for key, (old, _new) in TRANSITIONS.items()},
        )
        self.assertFalse(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").exists())

    def test_retained_values_are_preserved_and_all_listed_in_one_durable_warning(self) -> None:
        for key, value in CONFIGURED.items():
            result = SettingsService.update_setting(key, value)
            self.assertTrue(result.is_ok(), result)
        output = self.run_sync()
        alerts = AuditAlert.objects.filter(metadata__activation_version="wp18-v1")
        self.assertEqual(alerts.count(), 1)
        alert = alerts.get()
        self.assertEqual((alert.alert_type, alert.severity, alert.status), ("data_integrity", "warning", "active"))
        self.assertEqual(set(alert.metadata["keys"]), set(TRANSITIONS))
        self.assertEqual(alert.evidence["retained_values"], CONFIGURED)
        self.assertEqual(
            alert.evidence["previous_enforced_values"], {key: new for key, (_old, new) in TRANSITIONS.items()}
        )
        self.assertEqual(
            dict(SystemSetting.objects.filter(key__in=TRANSITIONS).values_list("key", "value")), CONFIGURED
        )
        for key in TRANSITIONS:
            self.assertIn(key, output)
            self.assertIn(key, alert.description)
        self.run_sync()
        self.assertEqual(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").count(), 1)
        self.assertEqual(SettingActivation.objects.filter(key__in=TRANSITIONS, completed_at__isnull=False).count(), 6)
