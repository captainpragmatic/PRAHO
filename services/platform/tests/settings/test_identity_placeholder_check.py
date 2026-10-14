"""A deployment still showing the example company contacts is warned about.

The catalog ships obvious placeholder contacts (``support@example.com``) so no deployment inherits
another operator's identity. Legal pages and the customer portal show them until staff set their
own, so the database check warns outside DEBUG. It is a warning, not an error:
``migrate`` runs database checks before migrating, and the deploy that seeds the placeholder must
still be able to finish so staff can reach the settings page.
"""

from __future__ import annotations

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.settings.checks import check_company_identity_placeholders
from apps.settings.models import SystemSetting


def _store(key: str, value: str) -> None:
    SystemSetting.objects.update_or_create(
        key=key,
        defaults={"name": key, "category": "company", "data_type": "string", "value": value, "default_value": ""},
    )


@override_settings(DEBUG=False)
class CompanyIdentityPlaceholderCheckTests(TestCase):
    def setUp(self) -> None:
        cache.clear()

    def test_placeholder_identity_is_warned_about(self) -> None:
        messages = check_company_identity_placeholders(databases=["default"])
        self.assertEqual([m.id for m in messages], ["settings.W001"])
        self.assertIn("company.email_support", messages[0].msg)
        self.assertIn("company.email_privacy", messages[0].msg)

    def test_configured_identity_passes(self) -> None:
        _store("company.email_support", "help@acme.test")
        _store("company.email_privacy", "privacy@acme.test")
        self.assertEqual(check_company_identity_placeholders(databases=["default"]), [])

    def test_a_stored_placeholder_still_warns(self) -> None:
        _store("company.email_support", "support@example.com")  # Seeded from the catalog default
        _store("company.email_privacy", "privacy@acme.test")
        messages = check_company_identity_placeholders(databases=["default"])
        self.assertEqual([m.id for m in messages], ["settings.W001"])
        self.assertNotIn("company.email_privacy", messages[0].msg)

    def test_check_stays_offline_unless_the_database_is_selected(self) -> None:
        self.assertEqual(check_company_identity_placeholders(databases=None), [])

    @override_settings(DEBUG=True)
    def test_development_is_not_warned(self) -> None:
        self.assertEqual(check_company_identity_placeholders(databases=["default"]), [])
