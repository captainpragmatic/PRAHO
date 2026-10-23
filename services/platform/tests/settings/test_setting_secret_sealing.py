"""A sensitive setting is sealed for its own row and field, or refused (#751 follow-up, secret hooks).

The settings save hook encrypted a sensitive value only when it did not start with "aes:", and only in
memory: a save that listed is_sensitive but not the value left the plaintext on disk under a row now
marked sensitive, which every later read fails to decrypt. A setting that becomes sensitive now writes
its value and default sealed with the flag; a value is kept only if it decrypts for this row and field;
settings setup carries on past one that cannot be sealed.
"""

from __future__ import annotations

from django.test import TestCase

from apps.common.encryption import EncryptionError
from apps.settings.catalog import CATALOG
from apps.settings.management.commands.setup_default_settings import _reconcile
from apps.settings.models import SystemSetting

KEY = "integrations.stripe_secret_key"  # A sensitive string setting


def _raw(key: str) -> object:
    return SystemSetting.objects.filter(key=key).values_list("value", flat=True).get()


class SettingSealTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.definition = next(item for item in CATALOG if item.key == KEY)
        SystemSetting.objects.filter(key=KEY).delete()

    def _plain_row(self, value: str) -> SystemSetting:
        """The row as it stood before the catalogue made it sensitive."""
        SystemSetting.objects.create(
            key=KEY, name=KEY, data_type="string", category="integrations", value="placeholder", default_value=""
        )
        SystemSetting.objects.filter(key=KEY).update(is_sensitive=False, value=value)
        return SystemSetting.objects.get(key=KEY)

    def test_a_setting_that_becomes_sensitive_is_sealed_on_disk(self) -> None:
        setting = self._plain_row("sk_live_plain")

        _reconcile(setting, self.definition, force=False, rewrite=False)

        raw = _raw(KEY)
        self.assertTrue(str(raw).startswith("aes:v2:"), f"stored in plaintext: {raw!r}")
        self.assertEqual(SystemSetting.objects.get(key=KEY).get_typed_value(), "sk_live_plain")

    def test_setup_goes_on_past_a_value_that_cannot_be_sealed(self) -> None:
        setting = self._plain_row("aes:v1:superseded")

        try:
            _reconcile(setting, self.definition, force=False, rewrite=False)
        except Exception as error:
            self.fail(f"one value that cannot be sealed must not stop settings setup ({type(error).__name__})")

        self.assertFalse(
            SystemSetting.objects.get(key=KEY).is_sensitive, "left as it was, not marked sensitive over a value it cannot seal"
        )

    def test_a_value_that_only_looks_like_ciphertext_is_refused(self) -> None:
        for value in ("aes:v1:superseded", "aes:v2:not-ciphertext"):
            SystemSetting.objects.filter(key=KEY).delete()
            with self.subTest(value=value), self.assertRaises(EncryptionError):
                SystemSetting(
                    key=KEY, name=KEY, data_type="string", category="integrations", value=value, default_value="",
                    is_sensitive=True,
                ).save()

    def test_another_rows_ciphertext_is_refused(self) -> None:
        other = SystemSetting.objects.create(
            key="integrations.stripe_webhook_secret", name="w", data_type="string", category="integrations",
            value="whsec_one", default_value="", is_sensitive=True,
        )

        with self.assertRaises(EncryptionError):
            SystemSetting(
                key=KEY, name=KEY, data_type="string", category="integrations", value=_raw(other.key),
                default_value="", is_sensitive=True,
            ).save()
