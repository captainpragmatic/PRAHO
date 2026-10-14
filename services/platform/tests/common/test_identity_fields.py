"""Phone and VAT numbers follow the customer's country, not Romania's (identity_fields.py, both services)."""

from __future__ import annotations

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase, override_settings

from apps.common.identity_fields import normalize_phone, normalize_vat_number, validate_international_phone
from apps.customers.forms import CustomerCreationForm
from apps.customers.models import CustomerAddress
from apps.orders.preflight import OrderPreflightValidationService
from apps.settings.models import SystemSetting


class PhoneTests(SimpleTestCase):
    def test_international_numbers_are_kept_for_any_country(self) -> None:
        for value, country, stored in (
            ("+49 30 1234567", "DE", "+49301234567"),
            ("+40.21.123.4567", "RO", "+40211234567"),
            ("0049 30 1234567", "", "+49301234567"),
            ("+49 (30) 123-4567", "DE", "+49301234567"),
        ):
            with self.subTest(value=value):
                self.assertEqual(normalize_phone(value, country), stored)

    def test_a_romanian_national_number_becomes_international(self) -> None:
        self.assertEqual(normalize_phone("0721 123 456", "RO"), "+40721123456")
        self.assertEqual(normalize_phone("0721 123 456", "România"), "+40721123456")

    def test_a_national_number_elsewhere_needs_its_country_code(self) -> None:
        for country in ("DE", ""):
            with self.subTest(country=country), self.assertRaises(ValidationError):
                normalize_phone("030 1234567", country)

    def test_blank_stays_blank_and_garbage_is_refused(self) -> None:
        self.assertEqual(normalize_phone("", "RO"), "")
        for value in ("+0123456789", "+12", "phone", "+" + "1" * 40, "+4072112345", "+407211234567"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                normalize_phone(value, "DE")

    def test_the_model_validator_accepts_only_the_stored_form(self) -> None:
        validate_international_phone("+40721123456")
        with self.assertRaises(ValidationError):
            validate_international_phone("0721123456")


class VATNumberTests(SimpleTestCase):
    def test_de_phone_and_vat_accepted_ro_national_phone_normalised_gr_vat_uses_el(self) -> None:
        self.assertEqual(normalize_vat_number("DE 136 695 976", "DE"), "DE136695976")
        self.assertEqual(normalize_vat_number("136695976", "DE"), "DE136695976")  # bare: the customer's country
        self.assertEqual(normalize_vat_number("12345674", "RO"), "RO12345674")
        self.assertEqual(normalize_vat_number("094259216", "GR"), "EL094259216")  # VIES calls Greece EL
        self.assertEqual(normalize_vat_number("GR123456789", "GR"), "GR123456789")  # not a VAT prefix: as entered
        self.assertEqual(normalize_phone("+49 30 1234567", "DE"), "+49301234567")
        self.assertEqual(normalize_phone("0721 123 456", "RO"), "+40721123456")

    def test_a_prefixed_number_is_checked_whatever_the_address(self) -> None:
        self.assertEqual(normalize_vat_number("RO12345674", "DE"), "RO12345674")
        with self.assertRaises(ValidationError):
            normalize_vat_number("DE123", "DE")

    def test_a_tax_id_outside_the_eu_is_kept_as_entered(self) -> None:
        self.assertEqual(normalize_vat_number("CHE-123.456.789", "CH"), "CHE-123.456.789")
        self.assertEqual(normalize_vat_number("12-3456789", "US"), "12-3456789")

    def test_a_romanian_number_with_a_wrong_check_digit_or_a_cnp_is_refused(self) -> None:
        for value in ("RO12345678", "RO1900101123457"):  # the second is a valid CNP, which stdnum alone accepts
            with self.subTest(value=value), self.assertRaises(ValidationError):
                normalize_vat_number(value, "RO")

    def test_blank_stays_blank_and_an_overlong_value_is_refused(self) -> None:
        self.assertEqual(normalize_vat_number("  ", "RO"), "")
        with self.assertRaises(ValidationError):
            normalize_vat_number("RO" + "1" * 40, "RO")


class CountryAwareStaffFormTests(TestCase):
    """Staff create a customer by its own country's rules, not Romania's."""

    def _data(self, **extra: object) -> dict[str, object]:
        return {
            "user_action": "create", "first_name": "Klara", "last_name": "Kunde", "email": "klara@example.test",
            "phone": "+49 30 1234567", "customer_type": "company", "company_name": "Kunde GmbH",
            "is_vat_payer": True, "vat_number": "136695976", "address_line1": "Beispielstr. 1", "city": "Berlin",
            "postal_code": "10115", "country": "Germany", "payment_terms": 30, "credit_limit": 0,
            "preferred_currency": "EUR", "data_processing_consent": True, **extra,
        }

    def test_a_german_company_needs_no_county_and_keeps_its_phone_and_vat_number(self) -> None:
        form = CustomerCreationForm(data=self._data())
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual((form.cleaned_data["phone"], form.cleaned_data["vat_number"]), ("+49301234567", "DE136695976"))

    def test_a_romanian_company_needs_its_county_and_gains_ro_and_plus_40(self) -> None:
        romanian = {"country": "Romania", "postal_code": "010001", "vat_number": "12345674", "phone": "0721 123 456"}
        form = CustomerCreationForm(data=self._data(**romanian))
        self.assertFalse(form.is_valid())
        self.assertIn("county", form.errors)
        form = CustomerCreationForm(data=self._data(**romanian, county="Sector 1"))
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual((form.cleaned_data["phone"], form.cleaned_data["vat_number"]), ("+40721123456", "RO12345674"))

    @override_settings(COMPANY_COUNTRY_CODE="DE")
    def test_a_german_operators_new_address_starts_in_germany(self) -> None:
        SystemSetting.objects.filter(key="system.default_country").delete()
        cache.clear()
        self.assertEqual(CustomerAddress().country, "Germany")


class CountyAtCheckoutTests(SimpleTestCase):
    def _billing(self, **extra: object) -> dict[str, object]:
        return {"contact_name": "Klara Kunde", "email": "klara@example.test", "address_line1": "Beispielstr. 1",
                "city": "Berlin", "postal_code": "10115", "country": "DE", **extra}

    def test_only_a_romanian_billing_address_needs_its_county_to_check_out(self) -> None:
        missing = OrderPreflightValidationService._missing_billing_fields  # the rule preflight applies
        self.assertEqual(missing(self._billing()), [])
        self.assertEqual(len(missing(self._billing(country="RO", postal_code="010001"))), 1)
