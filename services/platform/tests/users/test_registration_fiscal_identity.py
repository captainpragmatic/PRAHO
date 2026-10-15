"""A portal registration keeps the company identity it was given (CUI, trade registry number), and no CNP.

A company had no field for a CUI at all. Registration also asked Romanian individuals for their
CNP and kept it, encrypted, until the link was confirmed. Nothing needs it then: an individual's
e-Factura invoice states the statutory identifier when none is on file, and a CNP is asked for only
where a registrar requires one. Registration no longer collects it, so it neither waits in a
pending registration nor reaches the customer, whatever a client sends.
"""

from __future__ import annotations

from typing import Any

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.fiscal_identity import get_customer_fiscal_identity
from apps.customers.models import CustomerTaxProfile
from apps.settings.services import SettingsService
from apps.users import registration_confirmation
from apps.users.pending_registration import PendingRegistration
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.legal import publish_release

CNP = "1900101123457"
BAD_CNP = "1900101123458"  # Fails only its check digit
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
        self.terms = publish_release()

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
            str(row.pk),
            row.token(),
            NEW_PASSPHRASE,
            accepts_marketing=False,
            terms_accepted=True,
            terms_document_id=str(self.terms.pk),
        )

    # --- No CNP is collected -------------------------------------------------------------------

    def stored_text(self, row: PendingRegistration) -> str:
        """Everything the pending registration keeps, as text."""
        return str({field.name: getattr(row, field.name) for field in PendingRegistration._meta.fields})

    def test_submitted_cnp_is_neither_stored_nor_copied_to_the_customer(self) -> None:
        cases = {
            "romanian individual": individual(),
            "invalid cnp": individual(cnp=BAD_CNP),
            "company": registration(country="RO", cnp=CNP),
        }
        for name, data in cases.items():
            with self.subTest(name):
                cache.clear()
                data["user_data"]["email"] = f"{name.replace(' ', '-')}@example.test"
                data["customer_data"]["company_name"] = name.title()
                row = self.submitted_row(data)
                self.assertNotIn(data["customer_data"]["cnp"], self.stored_text(row))
                result = self.confirm(row)
                self.assertTrue(result.is_ok(), result)
                _user, customer = result.unwrap()
                self.assertEqual(get_customer_fiscal_identity(customer).cnp, "")
                profile = CustomerTaxProfile.objects.filter(customer=customer).first()
                self.assertIn(getattr(profile, "cnp", None), (None, ""))

    def test_a_cnp_handed_in_with_the_customer_data_is_dropped(self) -> None:
        from apps.users.services import SecureUserRegistrationService  # noqa: PLC0415

        result = SecureUserRegistrationService.submit_pending_registration(
            user_data={"email": "direct@example.test", "first_name": "Ana", "last_name": "Pop"},
            customer_data={"customer_type": "individual", "company_name": "Ana Pop", "cnp": CNP},
        )
        self.assertTrue(result.is_ok(), result)
        self.assertNotIn(CNP, self.stored_text(PendingRegistration.objects.get(email="direct@example.test")))

    def test_a_romanian_individual_needs_no_cnp(self) -> None:
        for country in ("RO", "Romania", "România", None):
            with self.subTest(country=country):
                cache.clear()
                PendingRegistration.objects.all().delete()
                data = individual(cnp="")
                if country is None:
                    del data["customer_data"]["country"]
                else:
                    data["customer_data"]["country"] = country
                self.assertEqual(self.submit(data).status_code, 202)

    def test_the_preview_never_shows_a_cnp(self) -> None:
        row = self.submitted_row(individual())
        details = registration_confirmation.preview(str(row.pk), row.token()).unwrap()
        self.assertNotIn("cnp", details)
        self.assertNotIn(CNP, str(details))

    def test_a_country_that_resolves_to_none_is_not_romania_and_not_refused(self) -> None:
        # The portal's country field is free text, and these were accepted before.
        for country in ("USA", "Deutschland"):
            with self.subTest(country=country):
                cache.clear()
                PendingRegistration.objects.all().delete()
                row = self.submitted_row(registration(country=country, cui=""))
                self.assertEqual(row.customer_data["country"], country)

    def test_a_missing_country_follows_the_default_country(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(SettingsService.update_setting("system.default_country", "DE").is_ok())
        cache.clear()
        data = individual(cnp="")
        del data["customer_data"]["country"]
        self.assertEqual(self.submit(data).status_code, 202)
        # The country the decision used is kept: confirmation must not resolve a different default.
        self.assertEqual(PendingRegistration.objects.get().customer_data["country"], "Germany")

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
        details = registration_confirmation.preview(str(row.pk), row.token()).unwrap()
        self.assertEqual(details["cui"], CUI)
        self.assertEqual(details["registration_number"], "J40/1234/2020")

    def test_a_cui_with_a_bad_check_digit_is_refused(self) -> None:
        response = self.submit(registration(cui="14399847"))
        self.assertEqual(response.status_code, 400)
        self.assertIn("cui", str(response.json()))

    def test_a_refusal_is_in_the_registration_language(self) -> None:
        # The portal shows Platform's message on the field, to the customer.
        response = self.submit({**registration(cui="14399847"), "language": "ro"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["errors"]["customer_data"]["cui"], ["Introduceți un CUI valid."])

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
