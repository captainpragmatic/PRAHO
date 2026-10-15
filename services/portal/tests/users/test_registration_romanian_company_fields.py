"""The registration form asks for no CNP, and opens the Romanian company identifiers only for Romania.

It asked Romanian individuals for their CNP; nothing needs it at registration, so the field is gone
(an older page's CNP is never sent on). The CUI and trade registry number are Romanian identifiers:
the page opens with them when the billing country, or the default country when none was given, is
Romania, and register-toggle.js follows the country field from then on.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.localisation_services import get_localisation_defaults
from apps.users.forms import CustomerRegistrationForm


@contextmanager
def defaults_in(country: str) -> Iterator[None]:
    """The deployment's default country, as the form and its country initial both read it."""
    defaults = replace(get_localisation_defaults(), default_country=country)
    with (
        patch("apps.users.forms.get_localisation_defaults", return_value=defaults),
        patch("apps.common.localisation_forms.get_localisation_defaults", return_value=defaults),
    ):
        yield


class RegistrationRomanianCompanyFieldsTests(SimpleTestCase):
    def test_the_form_has_no_cnp_field(self) -> None:
        self.assertNotIn("cnp", CustomerRegistrationForm().fields)

    def test_a_blank_country_follows_the_default_country(self) -> None:
        for default, shown in (("RO", True), ("DE", False)):
            with self.subTest(default=default), defaults_in(default):
                self.assertIs(CustomerRegistrationForm().asks_romanian_company_ids(), shown)
                self.assertIs(CustomerRegistrationForm(data={"country": ""}).asks_romanian_company_ids(), shown)

    def test_a_given_country_decides(self) -> None:
        for country, shown in (("România", True), ("RO", True), ("Germany", False), ("DE", False)):
            with self.subTest(country=country), defaults_in("RO"):
                self.assertIs(CustomerRegistrationForm(data={"country": country}).asks_romanian_company_ids(), shown)
