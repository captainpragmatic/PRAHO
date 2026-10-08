"""Retirement contract for WP18 settings with no enforcement point."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils.translation import override

from apps.settings.catalog import CATALOG, CATALOG_BY_KEY, GROUPS, defs_for_group
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_admin_user

# Independent of the command's manifest: removing an entry there must fail these tests.
WP18_RETIRED_KEYS = (
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
)


class RetiredSettingsCatalogTests(SimpleTestCase):
    def test_retired_keys_are_absent_from_catalog_defaults_and_groups(self) -> None:
        catalog_keys = {definition.key for definition in CATALOG}
        group_keys = {definition.key for group in GROUPS for definition in defs_for_group(group.slug)}
        for key in WP18_RETIRED_KEYS:
            with self.subTest(key=key):
                self.assertNotIn(key, catalog_keys)
                self.assertNotIn(key, CATALOG_BY_KEY)
                self.assertNotIn(key, SettingsService.DEFAULT_SETTINGS)
                self.assertNotIn(key, group_keys)

    def test_retired_keys_are_absent_from_lint_baselines(self) -> None:
        scripts = Path(__file__).resolve().parents[4] / "scripts"
        for name in ("settings_inert_baseline.txt", "settings_drift_baseline.txt", "settings_reader_baseline.txt"):
            entries = {
                line.split("|", 1)[0]
                for line in (scripts / name).read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
            for key in WP18_RETIRED_KEYS:
                with self.subTest(baseline=name, key=key):
                    self.assertNotIn(key, entries)


class RetiredSettingsLifecycleTests(TestCase):
    def _seed_retired_rows(self) -> None:
        for key in WP18_RETIRED_KEYS:
            SystemSetting.objects.update_or_create(
                key=key,
                defaults={
                    "name": "Retired setting",
                    "description": "Previously editable without an enforcement point",
                    "category": "advanced",
                    "data_type": "integer",
                    "value": 37,
                    "default_value": 37,
                },
            )

    def test_stored_retired_keys_are_absent_from_settings_ui(self) -> None:
        self._seed_retired_rows()
        self.client.force_login(create_admin_user(username="wp18_retirement_admin"))
        response = self.client.get(reverse("settings:group", args=["advanced"]))
        self.assertContains(response, "common.cache_timeout_medium")
        for key in WP18_RETIRED_KEYS:
            with self.subTest(surface="group", key=key):
                self.assertNotContains(response, key)
            with self.subTest(surface="search", key=key):
                search = self.client.get(reverse("settings:search"), {"q": key})
                self.assertNotContains(search, f"#setting-{key}")

    def test_sync_deletes_all_retired_rows_and_reports_each_key(self) -> None:
        self._seed_retired_rows()
        active = SystemSetting.objects.create(
            key="billing.invoice_payment_terms_days",
            name="Active setting",
            category="billing",
            data_type="integer",
            value=37,
            default_value=14,
        )
        output = StringIO()
        with override("en"):
            call_command("setup_default_settings", stdout=output)
        for key in WP18_RETIRED_KEYS:
            with self.subTest(key=key):
                self.assertFalse(SystemSetting.objects.filter(key=key).exists())
                self.assertIn(f"Deleted retired setting: {key}", output.getvalue())
        active.refresh_from_db()
        self.assertEqual(active.value, 37)
        second = StringIO()
        with override("en"):
            call_command("setup_default_settings", stdout=second)
        self.assertNotIn("Deleted retired setting:", second.getvalue())
        self.assertFalse(SystemSetting.objects.filter(key__in=WP18_RETIRED_KEYS).exists())

    def test_category_sync_retires_only_rows_in_the_requested_category(self) -> None:
        self._seed_retired_rows()
        retained_key = "users.credential_max_age_days"
        SystemSetting.objects.filter(key=retained_key).update(category="users")
        output = StringIO()
        with override("en"):
            call_command("setup_default_settings", category="advanced", stdout=output)
        for key in WP18_RETIRED_KEYS:
            if key == retained_key:
                continue
            with self.subTest(key=key):
                self.assertFalse(SystemSetting.objects.filter(key=key).exists())
                self.assertIn(f"Deleted retired setting: {key}", output.getvalue())
        self.assertEqual(SystemSetting.objects.get(key=retained_key).value, 37)
        self.assertNotIn(f"Deleted retired setting: {retained_key}", output.getvalue())
        final = StringIO()
        with override("en"):
            call_command("setup_default_settings", stdout=final)
        self.assertFalse(SystemSetting.objects.filter(key=retained_key).exists())
        self.assertIn(f"Deleted retired setting: {retained_key}", final.getvalue())
