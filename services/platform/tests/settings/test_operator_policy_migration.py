"""Data-migration tests for renamed invitation-policy settings."""

from __future__ import annotations

import importlib

from django.apps import apps
from django.test import TestCase

from apps.settings.models import SystemSetting


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


class OperatorPolicyMigrationTests(TestCase):
    """Existing overrides survive the split into accurately named policies."""

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
