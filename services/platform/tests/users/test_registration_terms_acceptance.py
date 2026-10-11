"""Confirming a registration records the Terms of Service version its confirmer accepted.

The portal sent terms_accepted and Platform dropped it: nothing recorded who accepted which
terms, or when. Acceptance belongs to whoever confirms the emailed link, the person choosing the
password, so it is recorded at confirmation, with the version the confirmer saw.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.audit.services import GDPRDeletionService, GDPRExportService
from apps.common.legal import TERMS_OF_SERVICE_VERSION
from apps.customers.models import Customer
from apps.users import registration_confirmation
from apps.users.models import CustomerMembership, User
from apps.users.pending_registration import PendingRegistration
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

NEW_PASSPHRASE = "Confirm-registration-2026!"
STALE_VERSION = "2020-01-01"


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class TermsAcceptanceTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.row = PendingRegistration.objects.create(
            email="terms@example.test",
            user_data={"first_name": "Ana", "last_name": "Pop", "phone": ""},
            customer_data={
                "customer_type": "company",
                "company_name": "Terms SRL",
                "vat_number": "",
                "billing_address": "Str. 1",
                "billing_city": "Cluj-Napoca",
                "billing_postal_code": "400001",
            },
            sent_at=timezone.now(),
        )

    def confirm(self, **terms: Any) -> Any:
        return registration_confirmation.confirm(
            str(self.row.pk),
            self.row.token(),
            NEW_PASSPHRASE,
            accepts_marketing=False,
            data_processing_consent=True,
            **terms,
        )

    def test_the_accepted_version_and_time_are_recorded_with_one_audit_event(self) -> None:
        before = timezone.now()
        result = self.confirm(terms_accepted=True, terms_version=TERMS_OF_SERVICE_VERSION)
        after = timezone.now()
        self.assertTrue(result.is_ok(), result)
        user = User.objects.get(email="terms@example.test")
        self.assertEqual(user.terms_version, TERMS_OF_SERVICE_VERSION)
        assert user.terms_accepted_at is not None
        self.assertTrue(before <= user.terms_accepted_at <= after)
        [event] = AuditEvent.objects.filter(action="terms_of_service_accepted")
        self.assertEqual(event.metadata["terms_version"], TERMS_OF_SERVICE_VERSION)
        self.assertEqual(event.metadata["registration_id"], str(self.row.pk))
        self.assertEqual(event.user_id, user.pk)
        # Every confirmation writes one, for the new user's preferences. The terms are set when the
        # user is created, so recording them adds no second one.
        self.assertEqual(AuditEvent.objects.filter(action="profile_updated", user=user).count(), 1)

    def test_a_version_the_confirmer_did_not_see_creates_nothing_and_keeps_the_link(self) -> None:
        result = self.confirm(terms_accepted=True, terms_version=STALE_VERSION)
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err().code, "terms_changed")
        self.assertFalse(User.objects.filter(email="terms@example.test").exists())
        self.assertFalse(AuditEvent.objects.filter(action="terms_of_service_accepted").exists())
        self.row.refresh_from_db()
        self.assertIsNone(self.row.consumed_at)
        self.assertTrue(self.confirm(terms_accepted=True, terms_version=TERMS_OF_SERVICE_VERSION).is_ok())

    def test_without_acceptance_no_account_is_created_and_the_link_stays_usable(self) -> None:
        result = self.confirm()
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err().code, "terms_required")
        self.assertFalse(User.objects.filter(email="terms@example.test").exists())
        self.row.refresh_from_db()
        self.assertIsNone(self.row.consumed_at)

    def test_the_api_answers_missing_acceptance_on_the_field(self) -> None:
        response = self.post_confirm()
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["code"], "validation_failed")
        self.assertIn("terms_accepted", response.json()["errors"])

    def test_an_audit_failure_rolls_the_account_back(self) -> None:
        from apps.audit.services import AuditService  # noqa: PLC0415

        real = AuditService.log_simple_event

        def failing(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("event_type", args[0] if args else None) == "terms_of_service_accepted":
                raise RuntimeError("audit store unavailable")
            return real(*args, **kwargs)

        with patch.object(AuditService, "log_simple_event", side_effect=failing), self.assertRaises(RuntimeError):
            self.confirm(terms_accepted=True, terms_version=TERMS_OF_SERVICE_VERSION)
        self.assertFalse(User.objects.filter(email="terms@example.test").exists())
        self.assertFalse(Customer.objects.filter(company_name="Terms SRL").exists())
        self.assertFalse(CustomerMembership.objects.exists())
        # The link was not spent: the same confirmation succeeds once the audit store is back.
        self.assertTrue(self.confirm(terms_accepted=True, terms_version=TERMS_OF_SERVICE_VERSION).is_ok())

    def test_the_preview_names_the_version_to_accept(self) -> None:
        details = registration_confirmation.preview(str(self.row.pk), self.row.token())
        assert details is not None
        self.assertEqual(details["terms_version"], TERMS_OF_SERVICE_VERSION)

    # --- API ------------------------------------------------------------------------------------

    def post_confirm(self, **overrides: Any) -> Any:
        body = {
            "registration_id": str(self.row.pk),
            "token": self.row.token(),
            "password": NEW_PASSPHRASE,
            "password_confirm": NEW_PASSPHRASE,
            "data_processing_consent": True,
            **overrides,
        }
        return self.portal_post("/api/users/register/confirm/", body)

    def test_the_api_records_acceptance(self) -> None:
        response = self.post_confirm(terms_accepted=True, terms_version=TERMS_OF_SERVICE_VERSION)
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(User.objects.get(email="terms@example.test").terms_version, TERMS_OF_SERVICE_VERSION)

    def test_the_api_refuses_acceptance_without_the_version(self) -> None:
        response = self.post_confirm(terms_accepted=True)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("terms_version", response.json()["errors"])
        self.assertFalse(User.objects.filter(email="terms@example.test").exists())

    def test_the_api_answers_a_changed_version_with_its_own_code(self) -> None:
        response = self.post_confirm(terms_accepted=True, terms_version=STALE_VERSION)
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.json()["code"], "terms_changed")

    # --- GDPR -----------------------------------------------------------------------------------

    def test_the_export_includes_acceptance_and_anonymisation_clears_it(self) -> None:
        self.assertTrue(self.confirm(terms_accepted=True, terms_version=TERMS_OF_SERVICE_VERSION).is_ok())
        user = User.objects.get(email="terms@example.test")
        profile = GDPRExportService._collect_user_data(user, {"include_profile": True})["user_profile"]
        self.assertEqual(profile["terms_version"], TERMS_OF_SERVICE_VERSION)
        self.assertEqual(profile["terms_accepted_at"], user.terms_accepted_at.isoformat())
        self.assertTrue(GDPRDeletionService._anonymize_user_data(user).is_ok())
        user.refresh_from_db()
        self.assertIsNone(user.terms_accepted_at)
        self.assertEqual(user.terms_version, "")
