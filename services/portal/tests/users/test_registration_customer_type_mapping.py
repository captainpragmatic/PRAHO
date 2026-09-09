"""CustomerRegistrationForm.register_customer() must send a platform-canonical customer_type.

Regression (#499): the portal form offers Romanian legal-entity values (srl/sa/ong) that the
platform registration serializer rejects — its ChoiceField accepts only individual/company/pfa/ngo.
The form's default is 'srl', so a real user submitting the default was rejected at the API and
bounced back to /register/. register_customer() now maps to canonical values before the API call.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.users.forms import CustomerRegistrationForm


class TestRegistrationCustomerTypeMapping(SimpleTestCase):
    def _valid_form(self, customer_type: str) -> CustomerRegistrationForm:
        data = {
            "email": "map@example.com",
            "first_name": "Ion",
            "last_name": "Popescu",
            "phone": "",
            "password1": "CorrectHorse12!",
            "password2": "CorrectHorse12!",
            "customer_type": customer_type,
            "company_name": "Test Entity",
            "address_line1": "Str. Test 1",
            "city": "Bucuresti",
            "county": "Bucuresti",
            "postal_code": "010001",
            "data_processing_consent": True,
            "terms_accepted": True,
        }
        # Individuals must supply a CNP (Romanian personal ID) per the form's own rule.
        if customer_type == "individual":
            data["cnp"] = "1960101223145"
        form = CustomerRegistrationForm(data=data)
        assert form.is_valid(), form.errors
        return form

    def _sent_customer_type(self, form: CustomerRegistrationForm) -> Any:
        with patch("apps.users.forms.api_client._make_request", return_value={"ok": True}) as mock_req:
            form.register_customer()
        _args, kwargs = mock_req.call_args
        return kwargs["data"]["customer_data"]["customer_type"]

    def test_srl_maps_to_company(self) -> None:
        self.assertEqual(self._sent_customer_type(self._valid_form("srl")), "company")

    def test_sa_maps_to_company(self) -> None:
        self.assertEqual(self._sent_customer_type(self._valid_form("sa")), "company")

    def test_ong_maps_to_ngo(self) -> None:
        self.assertEqual(self._sent_customer_type(self._valid_form("ong")), "ngo")

    def test_pfa_and_individual_pass_through(self) -> None:
        self.assertEqual(self._sent_customer_type(self._valid_form("pfa")), "pfa")
        self.assertEqual(self._sent_customer_type(self._valid_form("individual")), "individual")
