"""Exact-number VIES evidence has no database dependency."""

from django.test import SimpleTestCase

from apps.billing.vies_evidence import normalize_vat_number, vies_verified_for
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

    def test_none_profile(self) -> None:
        self.assertFalse(vies_verified_for(None, "DE123456789"))

    def test_empty_normalized_number_is_not_evidence(self) -> None:
        profile = CustomerTaxProfile(vat_number="---", vies_verification_status="valid")
        self.assertFalse(vies_verified_for(profile, ""))
        for value in (None, False, 0, ""):
            self.assertEqual(normalize_vat_number(value), "")
