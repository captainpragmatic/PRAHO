"""Registrar validation errors must not redisplay credentials."""

from django.template.loader import render_to_string
from django.test import SimpleTestCase

from apps.domains.forms import RegistrarForm


class RegistrarSecretRenderingTests(SimpleTestCase):
    def test_invalid_registrar_form_does_not_redisplay_secrets(self) -> None:
        secrets = {
            "api_key": "SubmittedAPIKey123!",
            "api_secret": "SubmittedAPISecret123!",
            "webhook_secret": "SubmittedWebhookSecret123!",
        }
        form = RegistrarForm(secrets)
        self.assertFalse(form.is_valid())
        rendered = render_to_string("domains/staff/registrar_form.html", {"form": form})

        for name, secret in secrets.items():
            with self.subTest(field=name):
                self.assertIn(f'name="{name}"', rendered)
                self.assertNotIn(secret, rendered)
                self.assertNotRegex(rendered, rf'<input\b[^>]*\bname="{name}"[^>]*\bvalue\s*=')
