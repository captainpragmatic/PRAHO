"""Data-migration tests for renamed invitation-policy settings."""

from __future__ import annotations

import importlib

from django.apps import apps
from django.core.cache import cache
from django.db.models.signals import post_save
from django.test import TestCase, override_settings

from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.settings.signals import handle_setting_saved

LOCMEM_TEST_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "operator-policy-migration-tests",
    }
}


def _setting(key: str, value: int) -> SystemSetting:
    return SystemSetting.objects.create(
        key=key,
        category="security",
        name=key,
        description=key,
        data_type="integer",
        value=value,
        default_value=value,
    )


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class OperatorPolicyMigrationTests(TestCase):
    """Existing overrides survive the split into accurately named policies."""

    def setUp(self) -> None:
        cache.clear()

    def _run_migration(self) -> None:
        migration = importlib.import_module("apps.settings.migrations.0006_rename_invitation_policy_settings")
        migration.migrate_policy_rows(apps, None)

    def test_old_values_seed_each_corresponding_policy(self) -> None:
        _setting("security.invitation_rate_limit_per_user", 7)
        _setting("security.welcome_invite_limit_per_user_per_hour", 2)

        self._run_migration()

        values = dict(
            SystemSetting.objects.filter(key__startswith="security.").values_list("key", "value")
        )
        self.assertEqual(values["security.membership_invitation_limit_per_inviter_per_hour"], 7)
        self.assertEqual(values["security.join_request_notification_limit_per_customer_per_hour"], 7)
        self.assertEqual(values["security.welcome_invite_limit_per_target_per_hour"], 2)
        self.assertNotIn("security.invitation_rate_limit_per_user", values)
        self.assertNotIn("security.welcome_invite_limit_per_user_per_hour", values)
        self.assertFalse(
            SystemSetting.objects.filter(
                key__in=(
                    "security.membership_invitation_limit_per_inviter_per_hour",
                    "security.join_request_notification_limit_per_customer_per_hour",
                    "security.welcome_invite_limit_per_target_per_hour",
                )
            ).exclude(category="advanced")
        )

    def test_existing_destination_override_wins(self) -> None:
        _setting("security.invitation_rate_limit_per_user", 7)
        _setting("security.membership_invitation_limit_per_inviter_per_hour", 4)
        _setting("security.join_request_notification_limit_per_customer_per_hour", 5)

        self._run_migration()

        self.assertEqual(
            SystemSetting.objects.get(
                key="security.membership_invitation_limit_per_inviter_per_hour"
            ).value,
            4,
        )
        self.assertEqual(
            SystemSetting.objects.get(
                key="security.join_request_notification_limit_per_customer_per_hour"
            ).value,
            5,
        )
        self.assertFalse(SystemSetting.objects.filter(key="security.invitation_rate_limit_per_user").exists())

    def test_migration_invalidates_cached_destination_defaults(self) -> None:
        destination_keys = (
            "security.membership_invitation_limit_per_inviter_per_hour",
            "security.join_request_notification_limit_per_customer_per_hour",
            "security.welcome_invite_limit_per_target_per_hour",
        )
        self.assertEqual(
            [SettingsService.get_integer_setting(key, 99) for key in destination_keys],
            [10, 10, 3],
        )
        _setting("security.invitation_rate_limit_per_user", 0)
        _setting("security.welcome_invite_limit_per_user_per_hour", 1)

        # Historical models used by RunPython do not emit the current model's
        # cache-invalidation signal. Reproduce that migration-time boundary.
        post_save.disconnect(handle_setting_saved, sender=SystemSetting)
        try:
            with self.captureOnCommitCallbacks(execute=True):
                self._run_migration()
        finally:
            post_save.connect(handle_setting_saved, sender=SystemSetting)

        self.assertEqual(
            [SettingsService.get_integer_setting(key, 99) for key in destination_keys],
            [0, 0, 1],
        )
