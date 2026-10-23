"""Settings setup survives a stored secret no key can decrypt (#751 follow-up, secret consumers).

When a setting stops being sensitive, setup decrypts its stored value to keep it as plain text. A value
stored under a superseded format raised there, uncaught: setup_initial_data stopped, and with it every
deploy. The setting is now left as it is, still sensitive, and the operator is told to re-enter it.
"""

from __future__ import annotations

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from apps.settings.catalog import CATALOG
from apps.settings.management.commands.setup_default_settings import _reconcile
from apps.settings.models import SettingActivation, SystemSetting

LEGACY_CIPHERTEXT = "aes:v1:bm90LXJlYWRhYmxl"


class UnreadableSecretReconcileTests(TestCase):
    def test_a_setting_no_longer_sensitive_with_an_unreadable_value_is_kept_and_setup_goes_on(self) -> None:
        definition = next(item for item in CATALOG if not item.sensitive and item.data_type == "string")
        SystemSetting.objects.filter(key=definition.key).delete()
        SystemSetting.objects.create(
            key=definition.key, name=definition.key, data_type="string", category="system", value="placeholder",
            default_value=definition.default,
        )
        # As a row stored under the superseded format holds it: value and default both in that format.
        SystemSetting.objects.filter(key=definition.key).update(
            is_sensitive=True, value=LEGACY_CIPHERTEXT, default_value=LEGACY_CIPHERTEXT
        )
        setting = SystemSetting.objects.get(key=definition.key)

        try:
            _reconcile(setting, definition, force=False, rewrite=False)
        except Exception as error:
            self.fail(f"one unreadable secret must not stop settings setup ({type(error).__name__})")

        stored = SystemSetting.objects.get(key=definition.key)
        self.assertTrue(stored.is_sensitive, "kept sensitive: its value is still ciphertext")
        self.assertEqual(stored.value, LEGACY_CIPHERTEXT)

    def test_setup_with_a_pending_activation_survives_an_unreadable_value(self) -> None:
        key = "notifications.max_name_length"  # Has a default-value activation still to run
        definition = next(item for item in CATALOG if item.key == key)
        SystemSetting.objects.filter(key=key).delete()
        SystemSetting.objects.create(
            key=key, name=key, data_type=definition.data_type, category="notifications", value=100,
            default_value=definition.default,
        )
        SystemSetting.objects.filter(key=key).update(
            is_sensitive=True, value=LEGACY_CIPHERTEXT, default_value=LEGACY_CIPHERTEXT
        )
        SettingActivation.objects.filter(key=key).delete()

        try:
            call_command("setup_default_settings", stdout=StringIO())
        except Exception as error:
            self.fail(f"one unreadable secret must not stop settings setup ({type(error).__name__})")

        self.assertTrue(SystemSetting.objects.get(key=key).is_sensitive)
