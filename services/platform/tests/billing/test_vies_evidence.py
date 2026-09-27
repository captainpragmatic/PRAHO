"""Exact-number VIES evidence has no database dependency."""

from django.test import SimpleTestCase

from apps.billing.vies_evidence import normalize_vat_number, vat_number_matches_country, vies_verified_for
from apps.customers.models import CustomerTaxProfile


class VIESEvidenceTests(SimpleTestCase):
    def test_valid_matching_number(self) -> None:
        profile = CustomerTaxProfile(vat_number="DE123456789", vies_verification_status="valid")
        self.assertTrue(vies_verified_for(profile, "DE123456789"))

    def test_valid_different_number(self) -> None:
        profile = CustomerTaxProfile(vat_number="DE123456789", vies_verification_status="valid")
        self.assertFalse(vies_verified_for(profile, "DE999999999"))

    def test_unconfirmed_statuses(self) -> None:
        for status in ("format_only", "pending", "invalid", "not_applicable"):
            with self.subTest(status=status):
                profile = CustomerTaxProfile(vat_number="DE123456789", vies_verification_status=status)
                self.assertFalse(vies_verified_for(profile, "DE123456789"))

    def test_separators_and_case_are_ignored(self) -> None:
        profile = CustomerTaxProfile(vat_number="de 123-456.789", vies_verification_status="valid")
        self.assertTrue(vies_verified_for(profile, "DE123456789"))

    def test_other_separators_do_not_match_evidence(self) -> None:
        for separator in ("/", "\t", "\n", "_"):
            with self.subTest(separator=repr(separator)):
                number = f"DE123{separator}456789"
                self.assertEqual(normalize_vat_number(number), number)
                profile = CustomerTaxProfile(vat_number=number, vies_verification_status="valid")
                self.assertFalse(vies_verified_for(profile, "DE123456789"))

    def test_number_issuing_country_matches_billing_country(self) -> None:
        for number, country, expected in (
            ("RO18189442", "DE", False),
            ("DE136695976", "DE", True),
            ("EL094259216", "GR", True),
            ("GR094259216", "EL", True),
            ("123456789B01", "NL", True),
            ("de 136-695.976", "de", True),
            ("", "DE", False),
            (None, "DE", False),
            ("DE136695976", "", False),
        ):
            with self.subTest(number=number, country=country):
                self.assertEqual(vat_number_matches_country(number, country), expected)

    def test_none_profile(self) -> None:
        self.assertFalse(vies_verified_for(None, "DE123456789"))

    def test_empty_normalized_number_is_not_evidence(self) -> None:
        profile = CustomerTaxProfile(vat_number="---", vies_verification_status="valid")
        self.assertFalse(vies_verified_for(profile, ""))
        for value in (None, False, 0, ""):
            self.assertEqual(normalize_vat_number(value), "")
