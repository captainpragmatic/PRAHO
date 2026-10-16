"""A customer's Romanian CUI is looked up at ANAF when saved, and ANAF's answer is recorded.

The lookup is queued when the CUI is new or changed, which also clears the previous CUI's
evidence. An unavailable or busy ANAF is asked again later, then the lookup is deferred. The answer
is written only while the profile still has the CUI that was asked about. Only a Romanian operator
looks companies up, while billing.anaf_lookup_enabled is on and ANAF is reachable.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.billing.config import anaf_lookup_enabled
from apps.billing.gateways.anaf_gateway import AnafCompany, AnafLookup
from apps.customers import anaf_verification
from apps.customers.models import Customer, CustomerTaxProfile
from apps.settings.services import SettingsService

CUI = "14399840"
OTHER_CUI = "18547290"
Status = CustomerTaxProfile.AnafStatus
COMPANY = AnafCompany(cui=CUI, name="DANTE INTERNATIONAL SA", registration_number="J2002000372404", vat_registered=True)


def answer(**kwargs: Any) -> AnafLookup:
    return AnafLookup(api_available=True, **kwargs)


@override_settings(ANAF_TRANSPORT_ENABLED=True, COMPANY_COUNTRY_CODE="RO")
class AnafVerificationTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Dante International SA", company_name="Dante International SA", customer_type="company"
        )
        self.schedule = self.enterContext(patch.object(anaf_verification, "schedule_lookup"))

    def profile_with(self, cui: str) -> CustomerTaxProfile:
        with self.captureOnCommitCallbacks(execute=True):
            profile, _ = CustomerTaxProfile.objects.update_or_create(customer=self.customer, defaults={"cui": cui})
        return profile

    def verify(self, profile: CustomerTaxProfile, result: AnafLookup, attempt: int = 1) -> str:
        with patch("apps.customers.anaf_verification.AnafGateway.lookup", return_value=result):
            return anaf_verification.verify_tax_profile_with_anaf(str(profile.pk), attempt)

    def test_cui_change_enqueues_lookup_writes_evidence_and_rate_limit_reschedules(self) -> None:
        profile = self.profile_with(CUI)
        self.schedule.assert_called_once_with(str(profile.pk))
        profile.refresh_from_db()
        self.assertEqual(profile.anaf_status, Status.PENDING)

        # ANAF busy: asked again after 30 s, then 2 min, 10 min and 1 h, then deferred.
        self.schedule.reset_mock()
        busy = AnafLookup(api_available=False, rate_limited=True)
        for attempt, delay in enumerate(anaf_verification.RETRY_DELAYS, start=1):
            self.assertEqual(self.verify(profile, busy, attempt), "rescheduled")
            self.schedule.assert_called_with(str(profile.pk), attempt=attempt + 1, delay=delay)
        self.assertEqual(anaf_verification.RETRY_DELAYS[0], timedelta(seconds=30))
        self.assertEqual(self.verify(profile, busy, len(anaf_verification.RETRY_DELAYS) + 1), "deferred")
        self.assertTrue(AuditEvent.objects.filter(action="anaf_lookup_deferred").exists())

        self.assertEqual(self.verify(profile, answer(companies={CUI: COMPANY})), Status.ACTIVE)
        profile.refresh_from_db()
        self.assertEqual(
            (profile.anaf_status, profile.anaf_verified_name, profile.anaf_vat_registered),
            (Status.ACTIVE, "DANTE INTERNATIONAL SA", True),
        )
        self.assertIsNotNone(profile.anaf_verified_at)
        event = AuditEvent.objects.get(action="anaf_lookup_completed")
        self.assertEqual(event.metadata["registration_number"], "J2002000372404")

        # A changed CUI drops the evidence and is looked up afresh.
        self.schedule.reset_mock()
        profile = self.profile_with(OTHER_CUI)
        self.schedule.assert_called_once_with(str(profile.pk))
        profile.refresh_from_db()
        self.assertEqual((profile.anaf_status, profile.anaf_verified_name, profile.anaf_verified_at), (Status.PENDING, "", None))

    def test_an_answer_for_a_cui_the_profile_no_longer_has_is_not_written(self) -> None:
        profile = self.profile_with(CUI)

        def cui_changes_meanwhile(cuis: list[str]) -> AnafLookup:
            CustomerTaxProfile.objects.filter(pk=profile.pk).update(cui=OTHER_CUI)
            return answer(companies={CUI: COMPANY})

        with patch("apps.customers.anaf_verification.AnafGateway.lookup", side_effect=cui_changes_meanwhile):
            self.assertEqual(anaf_verification.verify_tax_profile_with_anaf(str(profile.pk)), "stale")
        profile.refresh_from_db()
        self.assertEqual((profile.anaf_status, profile.anaf_verified_name), (Status.PENDING, ""))

    def test_inactive_and_unknown_companies(self) -> None:
        profile = self.profile_with(CUI)
        deregistered = AnafCompany(cui=CUI, name="Old SRL", deregistered_on="2020-01-01")
        self.assertEqual(self.verify(profile, answer(companies={CUI: deregistered})), Status.INACTIVE)
        self.assertEqual(self.verify(profile, answer(not_found=frozenset({CUI}))), Status.NOT_FOUND)
        profile.refresh_from_db()
        self.assertEqual((profile.anaf_verified_name, profile.anaf_vat_registered), ("", None))

    def test_the_setting_and_the_operator_country_switch_lookups_off(self) -> None:
        self.assertTrue(SettingsService.update_setting("billing.anaf_lookup_enabled", False).is_ok())
        self.assertFalse(anaf_lookup_enabled())
        profile = self.profile_with(CUI)
        self.schedule.assert_not_called()
        profile.refresh_from_db()
        self.assertEqual(profile.anaf_status, Status.NOT_CHECKED)
        self.assertEqual(anaf_verification.verify_tax_profile_with_anaf(str(profile.pk)), "disabled")

        self.assertTrue(SettingsService.update_setting("billing.anaf_lookup_enabled", True).is_ok())
        with override_settings(COMPANY_COUNTRY_CODE="DE"):
            self.profile_with(OTHER_CUI)
        self.schedule.assert_not_called()


@override_settings(ANAF_TRANSPORT_ENABLED=True, COMPANY_COUNTRY_CODE="RO")
class StaffAnafCheckTests(TestCase):
    def setUp(self) -> None:
        from apps.users.models import User  # noqa: PLC0415

        self.customer = Customer.objects.create(
            name="Dante International SA", company_name="Dante International SA", customer_type="company"
        )
        with patch.object(anaf_verification, "schedule_lookup"), self.captureOnCommitCallbacks(execute=True):
            self.profile = CustomerTaxProfile.objects.create(customer=self.customer, cui=CUI)
        staff = User.objects.create_user(
            email="anaf-staff@example.com", password="x", is_staff=True, staff_role="admin", is_superuser=True
        )
        self.client.force_login(staff)

    def test_the_button_records_anafs_answer_and_the_page_shows_it(self) -> None:
        from django.urls import reverse  # noqa: PLC0415

        with patch("apps.customers.anaf_verification.AnafGateway.lookup", return_value=answer(companies={CUI: COMPANY})):
            response = self.client.post(reverse("customers:anaf_verify", args=[self.customer.pk]))
        self.assertRedirects(response, reverse("customers:detail", args=[self.customer.pk]), fetch_redirect_response=False)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.anaf_status, Status.ACTIVE)

        page = self.client.get(reverse("customers:detail", args=[self.customer.pk])).content.decode()
        self.assertIn("DANTE INTERNATIONAL SA", page)
        self.assertIn(reverse("customers:anaf_verify", args=[self.customer.pk]), page)

        with override_settings(ANAF_TRANSPORT_ENABLED=False):
            page = self.client.get(reverse("customers:detail", args=[self.customer.pk])).content.decode()
            refused = self.client.post(reverse("customers:anaf_verify", args=[self.customer.pk]))
        self.assertNotIn(reverse("customers:anaf_verify", args=[self.customer.pk]), page)
        self.assertEqual(refused.status_code, 302)
        self.assertEqual(self.client.get(reverse("customers:anaf_verify", args=[self.customer.pk])).status_code, 405)
