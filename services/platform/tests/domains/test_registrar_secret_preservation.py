"""Registrar edits preserve encrypted secrets when replacement inputs are blank."""

from typing import ClassVar

from django.template.loader import render_to_string
from django.test import TestCase, override_settings

from apps.common.encryption import decrypt_value, encrypt_value
from apps.domains.forms import RegistrarForm
from apps.domains.models import Registrar


@override_settings(
    ENCRYPTION_KEYS=["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
    LANGUAGE_CODE="en",
)
class RegistrarSecretPreservationTests(TestCase):
    secrets: ClassVar[dict[str, str]] = {
        "api_key": "StoredAPIKey123!",
        "api_secret": "StoredAPISecret123!",
        "webhook_secret": "StoredWebhookSecret123!",
    }

    def setUp(self) -> None:
        self.registrar = Registrar.objects.create(
            name="existing-registrar",
            display_name="Existing Registrar",
            website_url="https://example.com",
            api_endpoint="https://api.example.com",
            default_nameservers=["ns1.example.com"],
            **{name: encrypt_value(value) or "" for name, value in self.secrets.items()},
        )

    def _data(self, name: str = "existing-registrar") -> dict[str, str]:
        return {
            "name": name,
            "display_name": "Renamed Registrar",
            "website_url": "https://example.com",
            "api_endpoint": "https://api.example.com",
            "api_username": "",
            "api_key": "",
            "api_secret": "",
            "webhook_secret": "",
            "webhook_endpoint": "",
            "status": "active",
            "default_nameservers": '["ns1.example.com"]',
            "currency": "USD",
            "monthly_fee_cents": "0",
        }

    def test_display_name_edit_preserves_blank_secrets_with_either_save_mode(self) -> None:
        for commit in (True, False):
            with self.subTest(commit=commit):
                self.registrar.refresh_from_db()
                original = {name: getattr(self.registrar, name) for name in self.secrets}
                form = RegistrarForm(self._data(), instance=self.registrar)
                self.assertTrue(form.is_valid(), form.errors)

                saved = form.save(commit=commit)
                for name, plaintext in self.secrets.items():
                    self.assertEqual(decrypt_value(getattr(saved, name)), plaintext)
                    self.assertEqual(getattr(saved, name), original[name])

                if not commit:
                    saved.save()
                saved.refresh_from_db()
                self.assertEqual(saved.display_name, "Renamed Registrar")
                for name, plaintext in self.secrets.items():
                    self.assertEqual(decrypt_value(getattr(saved, name)), plaintext)
                    self.assertEqual(getattr(saved, name), original[name])

    def test_replacing_each_secret_preserves_the_other_blank_secrets(self) -> None:
        for replaced in self.secrets:
            with self.subTest(replaced=replaced):
                registrar = Registrar.objects.get(pk=self.registrar.pk)
                registrar.set_encrypted_credentials(**self.secrets)
                registrar.save()
                original = {name: getattr(registrar, name) for name in self.secrets}
                replacement = f"Replacement-{replaced}-123!"
                data = self._data()
                data[replaced] = replacement
                form = RegistrarForm(data, instance=registrar)
                self.assertTrue(form.is_valid(), form.errors)

                saved = form.save()
                saved.refresh_from_db()
                ciphertext = getattr(saved, replaced)
                self.assertTrue(ciphertext.startswith("aes:"))
                self.assertNotEqual(ciphertext, replacement)
                self.assertNotEqual(ciphertext, original[replaced])
                self.assertEqual(decrypt_value(ciphertext), replacement)

                for name, plaintext in self.secrets.items():
                    if name != replaced:
                        self.assertEqual(decrypt_value(getattr(saved, name)), plaintext)
                        self.assertEqual(getattr(saved, name), original[name])

    def test_creation_encrypts_secrets_and_a_later_blank_edit_preserves_them(self) -> None:
        data = self._data("new-registrar")
        data.update(self.secrets)
        form = RegistrarForm(data)
        self.assertTrue(form.is_valid(), form.errors)

        registrar = form.save()
        registrar.refresh_from_db()
        original: dict[str, str] = {}
        for name, plaintext in self.secrets.items():
            ciphertext = getattr(registrar, name)
            self.assertTrue(ciphertext.startswith("aes:"))
            self.assertNotEqual(ciphertext, plaintext)
            self.assertEqual(decrypt_value(ciphertext), plaintext)
            original[name] = ciphertext

        edit = RegistrarForm(self._data("new-registrar"), instance=registrar)
        self.assertTrue(edit.is_valid(), edit.errors)
        saved = edit.save()
        saved.refresh_from_db()
        for name, plaintext in self.secrets.items():
            self.assertEqual(decrypt_value(getattr(saved, name)), plaintext)
            self.assertEqual(getattr(saved, name), original[name])

    def test_unbound_edit_does_not_prefill_encrypted_secrets(self) -> None:
        form = RegistrarForm(instance=self.registrar)
        for name in self.secrets:
            with self.subTest(field=name):
                self.assertEqual(form[name].value(), "")

    def test_edit_template_explains_blank_secret_retention_for_all_three_fields(self) -> None:
        form = RegistrarForm(instance=self.registrar)
        rendered = render_to_string(
            "domains/staff/registrar_form.html",
            {"form": form, "is_edit": True},
        )
        self.assertEqual(rendered.count("Leave blank to keep the existing secret."), 3)
        for name, plaintext in self.secrets.items():
            self.assertIn(f'name="{name}"', rendered)
            self.assertNotIn(plaintext, rendered)
            self.assertNotIn(getattr(self.registrar, name), rendered)
