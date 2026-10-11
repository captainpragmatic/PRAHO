"""A portal registration keeps the fiscal identity it was given: CNP, CUI and trade registry number.

The portal requires a CNP from Romanian individuals and sends it, but the registration serializer
did not declare it, so DRF dropped it. Every individual who registered through the portal was then
invoiced with the placeholder CNP. A company had no field for a CUI at all.

The CNP waits for confirmation encrypted, bound to its row, and never in the plain JSON.
"""

from __future__ import annotations

from typing import Any

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.fiscal_identity import get_customer_fiscal_identity
from apps.common.encryption import encrypt_sensitive_data
from apps.settings.services import SettingsService
from apps.users import registration_confirmation
from apps.users.models import User
from apps.users.pending_registration import PendingRegistration
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

CNP = "1900101123457"
OTHER_CNP = "2900505123403"
BAD_CNPS = ("1900101123458", "2900505123404")  # Each fails only its check digit
CUI = "14399840"
NEW_PASSPHRASE = "Confirm-registration-2026!"


def registration(**customer: Any) -> dict[str, Any]:
    return {
        "user_data": {"email": "ana@example.test", "first_name": "Ana", "last_name": "Pop", "phone": ""},
        "customer_data": {
            "customer_type": "company",
            "company_name": "Ana Pop",
            "vat_number": "",
            "address_line1": "Str. Victoriei 10",
            "city": "Cluj-Napoca",
            "postal_code": "400001",
            "data_processing_consent": True,
            # A Romanian company gives a VAT number or a CUI.
            **({} if customer.get("vat_number") or customer.get("customer_type") == "individual" else {"cui": CUI}),
            **customer,
        },
    }


def individual(**customer: Any) -> dict[str, Any]:
    return registration(**{"customer_type": "individual", "country": "RO", "cnp": CNP, **customer})


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class RegistrationFiscalIdentityTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def submit(self, data: dict[str, Any]) -> Any:
        return self.portal_post("/api/customers/register/", data)

    def submitted_row(self, data: dict[str, Any]) -> PendingRegistration:
        response = self.submit(data)
        self.assertEqual(response.status_code, 202, response.content)
        row = PendingRegistration.objects.get(email=data["user_data"]["email"])
        PendingRegistration.objects.filter(pk=row.pk).update(sent_at=timezone.now())
        row.refresh_from_db()
        return row

    def confirm(self, row: PendingRegistration) -> Any:
        return registration_confirmation.confirm(
            str(row.pk), row.token(), NEW_PASSPHRASE, accepts_marketing=False, data_processing_consent=True
        )

    # --- The CNP reaches the customer, and never the plain JSON -------------------------------

    def test_a_romanian_individual_is_invoiced_with_their_cnp(self) -> None:
        row = self.submitted_row(individual())
        result = self.confirm(row)
        self.assertTrue(result.is_ok(), result)
        _user, customer = result.unwrap()
        self.assertEqual(get_customer_fiscal_identity(customer).cnp, CNP)

    def test_the_cnp_waits_encrypted_and_bound_to_its_row(self) -> None:
        row = self.submitted_row(individual())
        self.assertNotIn("cnp", row.customer_data)
        self.assertNotIn(CNP, str(row.customer_data))
        self.assertTrue(row.cnp_encrypted.startswith("aes:v2:"), row.cnp_encrypted[:10])
        self.assertEqual(row.cnp(), CNP)

    def test_the_column_is_cleared_when_the_link_is_used(self) -> None:
        row = self.submitted_row(individual())
        self.assertTrue(self.confirm(row).is_ok())
        stored = PendingRegistration.objects.values_list("cnp_encrypted", "consumed_at").get(pk=row.pk)
        self.assertEqual(stored[0], "")
        self.assertIsNotNone(stored[1])

    def test_a_cnp_handed_in_with_the_customer_data_is_still_encrypted(self) -> None:
        from apps.users.services import SecureUserRegistrationService  # noqa: PLC0415

        result = SecureUserRegistrationService.submit_pending_registration(
            user_data={"email": "direct@example.test", "first_name": "Ana", "last_name": "Pop"},
            customer_data={"customer_type": "individual", "company_name": "Ana Pop", "cnp": CNP},
        )
        self.assertTrue(result.is_ok(), result)
        row = PendingRegistration.objects.get(email="direct@example.test")
        self.assertNotIn("cnp", row.customer_data)
        self.assertEqual(row.cnp(), CNP)

    def test_the_preview_never_shows_the_cnp(self) -> None:
        row = self.submitted_row(individual())
        details = registration_confirmation.preview(str(row.pk), row.token())
        assert details is not None
        self.assertNotIn("cnp", details)
        self.assertNotIn(CNP, str(details))

    # --- A ciphertext that is not this row's is refused, and the link is spent ----------------

    def assert_refused_and_spent(self, row: PendingRegistration) -> None:
        result = self.confirm(row)
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err().code, "details_unavailable")
        self.assertFalse(User.objects.filter(email=row.email).exists())
        row.refresh_from_db()
        self.assertIsNotNone(row.consumed_at, "an unreadable CNP must not leave the link usable")
        self.assertEqual(row.cnp_encrypted, "")
        self.assertTrue(AuditEvent.objects.filter(action="pending_registration_cnp_unreadable").exists())

    def test_ciphertext_moved_from_another_row_is_refused(self) -> None:
        donor = PendingRegistration.objects.create(email="donor@example.test")
        donor.set_cnp(OTHER_CNP)
        donor.save()
        row = self.submitted_row(individual())
        PendingRegistration.objects.filter(pk=row.pk).update(cnp_encrypted=donor.cnp_encrypted)
        row.refresh_from_db()
        self.assert_refused_and_spent(row)

    def test_ciphertext_without_a_row_binding_is_refused(self) -> None:
        row = self.submitted_row(individual())
        PendingRegistration.objects.filter(pk=row.pk).update(cnp_encrypted=encrypt_sensitive_data(OTHER_CNP))
        row.refresh_from_db()
        self.assert_refused_and_spent(row)

    # --- Who needs a CNP ----------------------------------------------------------------------

    def test_a_romanian_individual_must_give_a_cnp(self) -> None:
        for country in ("RO", "Romania", "România", None):
            with self.subTest(country=country):
                data = individual(cnp="")
                if country is None:
                    del data["customer_data"]["country"]
                else:
                    data["customer_data"]["country"] = country
                response = self.submit(data)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertIn("cnp", str(response.json()))
        self.assertFalse(PendingRegistration.objects.exists())

    def test_an_individual_outside_romania_needs_no_cnp_and_keeps_none(self) -> None:
        row = self.submitted_row(individual(country="DE", cnp=CNP))
        self.assertEqual(row.cnp_encrypted, "")

    def test_a_country_that_resolves_to_none_is_not_romania_and_not_refused(self) -> None:
        # The portal's country field is free text, and these were accepted before.
        for country in ("USA", "Deutschland"):
            with self.subTest(country=country):
                cache.clear()
                PendingRegistration.objects.all().delete()
                row = self.submitted_row(individual(country=country, cnp=""))
                self.assertEqual(row.cnp_encrypted, "")

    def test_a_missing_country_follows_the_default_country(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(SettingsService.update_setting("system.default_country", "DE").is_ok())
        cache.clear()
        data = individual(cnp="")
        del data["customer_data"]["country"]
        self.assertEqual(self.submit(data).status_code, 202)
        # The country the decision used is kept: confirmation must not resolve a different default.
        self.assertEqual(PendingRegistration.objects.get().customer_data["country"], "Germany")

    def test_non_ascii_digits_get_the_fixed_answer(self) -> None:
        response = self.submit(individual(cnp="190010112345\u00b2"))
        self.assertEqual(response.status_code, 400)
        self.assertIn("cnp", response.json()["errors"]["customer_data"])

    def test_a_company_keeps_no_cnp(self) -> None:
        row = self.submitted_row(registration(country="RO", cnp=CNP))
        self.assertEqual(row.cnp_encrypted, "")

    def test_a_bad_cnp_gets_one_fixed_answer_that_repeats_none_of_it(self) -> None:
        bodies = []
        for bad in BAD_CNPS:
            response = self.submit(individual(cnp=bad))
            self.assertEqual(response.status_code, 400)
            body = response.content.decode()
            self.assertNotIn(bad[:7], body)
            self.assertNotIn(bad[-6:], body)
            bodies.append(body)
        self.assertEqual(bodies[0], bodies[1])

    # --- CUI and trade registry number --------------------------------------------------------

    def test_a_company_with_a_cui_and_no_vat_number_is_invoiced_with_its_cui(self) -> None:
        row = self.submitted_row(registration(cui=f"RO{CUI}", registration_number="j40/1234/2020"))
        self.assertEqual(row.customer_data["cui"], CUI)
        result = self.confirm(row)
        self.assertTrue(result.is_ok(), result)
        _user, customer = result.unwrap()
        profile = customer.tax_profile
        self.assertEqual(profile.cui, CUI)
        self.assertEqual(profile.registration_number, "J40/1234/2020")
        self.assertFalse(profile.is_vat_payer)
        self.assertEqual(get_customer_fiscal_identity(customer).business_tax_id, CUI)

    def test_the_preview_shows_the_cui_and_registry_number(self) -> None:
        row = self.submitted_row(registration(cui=CUI, registration_number="J40/1234/2020"))
        details = registration_confirmation.preview(str(row.pk), row.token())
        assert details is not None
        self.assertEqual(details["cui"], CUI)
        self.assertEqual(details["registration_number"], "J40/1234/2020")

    def test_a_cui_with_a_bad_check_digit_is_refused(self) -> None:
        response = self.submit(registration(cui="14399847"))
        self.assertEqual(response.status_code, 400)
        self.assertIn("cui", str(response.json()))

    def test_a_vat_number_for_another_cui_is_refused(self) -> None:
        response = self.submit(registration(cui=CUI, vat_number="RO18547290"))
        self.assertEqual(response.status_code, 400)
        self.assertIn("cui", response.json()["errors"]["customer_data"])
        cache.clear()
        self.assertEqual(self.submit(registration(cui=CUI, vat_number=f"RO{CUI}")).status_code, 202)

    def test_a_romanian_company_needs_a_vat_number_or_a_cui(self) -> None:
        response = self.submit(registration(country="RO", cui=""))
        self.assertEqual(response.status_code, 400)
        self.assertIn("cui", response.json()["errors"]["customer_data"])
        self.assertFalse(PendingRegistration.objects.exists())

    def test_a_company_abroad_needs_neither(self) -> None:
        row = self.submitted_row(registration(country="DE", cui=""))
        self.assertEqual(row.customer_data["cui"], "")

    def test_an_individual_keeps_no_company_identifiers(self) -> None:
        row = self.submitted_row(individual(cui=CUI, registration_number="J40/1234/2020"))
        self.assertNotIn("cui", row.customer_data)
        self.assertNotIn("registration_number", row.customer_data)
