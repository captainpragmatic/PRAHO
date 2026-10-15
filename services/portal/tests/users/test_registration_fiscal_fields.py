"""The registration form asks for the fiscal identity each customer type has, and shows Platform's refusals.

A company gives a VAT number or a CUI (with its trade registry number); an individual gives none,
and no CNP is asked for. Platform checks them in full (checksums, VAT/CUI agreement); a refusal used
to reach the customer as "Registration failed" with no field named, so it is now shown on the field.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.api_client.services import PlatformAPIError
from apps.users.forms import CustomerRegistrationForm

CNP = "1960101223143"  # Posted by an older page; never sent on
CUI = "14399840"


def form_data(**overrides: Any) -> dict[str, Any]:
    return {
        "email": "fiscal@example.com",
        "first_name": "Ion",
        "last_name": "Popescu",
        "phone": "",
        "password1": "CorrectHorse12!",
        "password2": "CorrectHorse12!",
        "customer_type": "srl",
        "company_name": "Fiscal SRL",
        "address_line1": "Str. Test 1",
        "city": "Bucuresti",
        "county": "Bucuresti",
        "postal_code": "010001",
        "country": "România",
        "data_processing_consent": True,
        "terms_accepted": True,
        **overrides,
    }


def sent_customer_data(form: CustomerRegistrationForm) -> dict[str, Any]:
    with patch("apps.users.forms.api_client._make_request", return_value={"success": True}) as request:
        form.register_customer()
    return request.call_args.kwargs["data"]["customer_data"]


class RegistrationFiscalFieldsTests(SimpleTestCase):
    def test_a_company_sends_its_cui_and_trade_registry_number(self) -> None:
        form = CustomerRegistrationForm(data=form_data(cui=f"RO{CUI}", trade_registry_number="j40/1234/2020"))
        self.assertTrue(form.is_valid(), form.errors)
        sent = sent_customer_data(form)
        self.assertEqual(sent["cui"], CUI)
        self.assertEqual(sent["registration_number"], "J40/1234/2020")

    def test_a_romanian_company_needs_a_vat_number_or_a_cui(self) -> None:
        form = CustomerRegistrationForm(data=form_data())
        self.assertFalse(form.is_valid())
        self.assertIn("cui", form.errors)
        self.assertTrue(CustomerRegistrationForm(data=form_data(vat_number=f"RO{CUI}")).is_valid())
        self.assertTrue(CustomerRegistrationForm(data=form_data(cui=CUI)).is_valid())

    def test_a_company_abroad_needs_neither(self) -> None:
        form = CustomerRegistrationForm(data=form_data(country="Germany", postal_code="10115"))
        self.assertTrue(form.is_valid(), form.errors)

    def test_an_individual_in_romania_gives_no_cnp_and_sends_no_identifiers(self) -> None:
        data = form_data(customer_type="individual", cui=CUI, trade_registry_number="J40/1234/2020", cnp=CNP)
        form = CustomerRegistrationForm(data=data)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertNotIn("cnp", form.fields)
        sent = sent_customer_data(form)
        self.assertNotIn("cnp", sent)
        self.assertNotIn(CNP, str(sent))
        self.assertEqual((sent["cui"], sent["registration_number"]), ("", ""))

    def test_identifiers_that_do_not_apply_raise_no_errors(self) -> None:
        # An individual abroad leaving junk in the hidden CUI field.
        data = form_data(customer_type="individual", country="Germany", postal_code="10115", cui="x")
        form = CustomerRegistrationForm(data=data)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(sent_customer_data(form)["cui"], "")

    def test_a_spaced_cui_is_accepted(self) -> None:
        form = CustomerRegistrationForm(data=form_data(cui="RO 14 399 840"))
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["cui"], CUI)

    def test_platform_user_errors_are_shown_on_the_fields(self) -> None:
        form = CustomerRegistrationForm(data=form_data(cui=CUI))
        self.assertTrue(form.is_valid(), form.errors)
        refusal = PlatformAPIError(
            "Validation failed",
            status_code=400,
            response_data={"errors": {"user_data": {"email": ["Enter a valid email address."]}}},
        )
        with patch("apps.users.forms.api_client._make_request", side_effect=refusal):
            self.assertIsNone(form.register_customer())
        self.assertEqual(form.errors["email"], ["Enter a valid email address."])

    def test_platform_field_errors_are_shown_on_the_fields(self) -> None:
        form = CustomerRegistrationForm(data=form_data(cui=CUI, trade_registry_number="J40/1234/2020"))
        self.assertTrue(form.is_valid(), form.errors)
        refusal = PlatformAPIError(
            "Validation failed",
            status_code=400,
            response_data={
                "success": False,
                "errors": {"customer_data": {"cui": ["Enter a valid CUI."], "registration_number": ["Bad."]}},
            },
        )
        with patch("apps.users.forms.api_client._make_request", side_effect=refusal):
            self.assertIsNone(form.register_customer())
        self.assertEqual(form.errors["cui"], ["Enter a valid CUI."])
        self.assertEqual(form.errors["trade_registry_number"], ["Bad."])
