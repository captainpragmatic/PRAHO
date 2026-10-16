"""Confirming a registration records exactly which Terms of Service release its confirmer accepted.

Acceptance belongs to whoever confirms the emailed link, the person choosing the password, so it is
recorded at confirmation. The preview names the release in force in the registration's language;
confirming refuses any other, so the record always names text the confirmer could read (ADR-0061).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.audit.services import GDPRDeletionService, GDPRExportService
from apps.common.legal import LegalDocument
from apps.customers.models import Customer
from apps.users import registration_confirmation
from apps.users.models import CustomerMembership, User
from apps.users.pending_registration import PendingRegistration
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.legal import publish_release

NEW_PASSPHRASE = "Confirm-registration-2026!"


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class TermsDocumentTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.terms = publish_release()
        self.row = self.pending()

    def pending(self, language: str = "en") -> PendingRegistration:
        return PendingRegistration.objects.create(
            email=f"terms-{language}@example.test",
            user_data={"first_name": "Ana", "last_name": "Pop", "phone": ""},
            customer_data={
                "customer_type": "company",
                "company_name": f"Terms {language} SRL",
                "vat_number": "",
                "billing_address": "Str. 1",
                "billing_city": "Cluj-Napoca",
                "billing_postal_code": "400001",
            },
            language=language,
            sent_at=timezone.now(),
        )

    def confirm(self, row: PendingRegistration | None = None, **terms: Any) -> Any:
        row = row or self.row
        return registration_confirmation.confirm(
            str(row.pk),
            row.token(),
            NEW_PASSPHRASE,
            accepts_marketing=False,
            **terms,
        )

    def accept(self, document: LegalDocument, row: PendingRegistration | None = None) -> Any:
        return self.confirm(row, terms_accepted=True, terms_document_id=str(document.pk))

    def previewed(self, row: PendingRegistration) -> Any:
        return registration_confirmation.preview(str(row.pk), row.token()).unwrap()["terms_document"]

    def test_confirm_records_document_reference_and_refuses_superseded_or_other_language_document(self) -> None:
        # A Romanian registration sees the English release while there is no Romanian one.
        romanian_row = self.pending("ro")
        self.assertEqual(self.previewed(romanian_row), self.terms.reference())

        # Once a Romanian release is in force, the English one is another language's text.
        romanian = publish_release(language="ro")
        self.assertEqual(self.previewed(romanian_row), romanian.reference())
        self.assertEqual(self.accept(self.terms, romanian_row).unwrap_err().code, "terms_changed")

        # A newer English release supersedes the one an English confirmer was shown.
        newer = publish_release(body_markdown="Newer terms.")
        result = self.accept(self.terms)
        self.assertEqual(result.unwrap_err().code, "terms_changed")
        self.assertFalse(User.objects.filter(email=self.row.email).exists())
        self.assertFalse(AuditEvent.objects.filter(action="terms_of_service_accepted").exists())
        self.row.refresh_from_db()
        self.assertIsNone(self.row.consumed_at)  # The same link works once the new terms are read

        before = timezone.now()
        self.assertTrue(self.accept(newer).is_ok())
        user = User.objects.get(email=self.row.email)
        self.assertEqual(user.terms_document, newer)
        assert user.terms_accepted_at is not None
        self.assertTrue(before <= user.terms_accepted_at <= timezone.now())
        [event] = AuditEvent.objects.filter(action="terms_of_service_accepted")
        self.assertEqual(event.metadata["terms_document"], newer.reference())
        self.assertEqual(event.metadata["registration_id"], str(self.row.pk))
        self.assertEqual(event.user_id, user.pk)
        # Every confirmation writes one, for the new user's preferences. The terms are set when the
        # user is created, so recording them adds no second one.
        self.assertEqual(AuditEvent.objects.filter(action="profile_updated", user=user).count(), 1)

        self.assertTrue(self.accept(romanian, romanian_row).is_ok())
        self.assertEqual(User.objects.get(email=romanian_row.email).terms_document, romanian)

    def test_while_no_terms_are_in_force_nobody_registers_or_confirms(self) -> None:
        row = self.pending("ro")
        with patch("apps.users.registration_confirmation.current_legal_document", return_value=None):
            preview = registration_confirmation.preview(str(row.pk), row.token())
            self.assertEqual(preview.unwrap_err().code, "terms_unavailable")
            self.assertEqual(self.accept(self.terms, row).unwrap_err().code, "terms_unavailable")
        self.assertFalse(User.objects.filter(email=row.email).exists())

        registration = {
            "user_data": {"email": "early@example.test", "first_name": "Ana", "last_name": "Pop", "phone": ""},
            "customer_data": {
                "customer_type": "company",
                "company_name": "Early SRL",
                "address_line1": "Str. 1",
                "city": "Berlin",
                "postal_code": "10115",
                "country": "DE",
            },
        }
        with patch("apps.users.services.current_legal_document", return_value=None):
            response = self.portal_post("/api/customers/register/", registration)
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("once the Terms of Service are published", response.content.decode())
        self.assertFalse(PendingRegistration.objects.filter(email="early@example.test").exists())

    def test_without_acceptance_no_account_is_created_and_the_link_stays_usable(self) -> None:
        result = self.confirm()
        self.assertEqual(result.unwrap_err().code, "terms_required")
        self.assertFalse(User.objects.filter(email=self.row.email).exists())
        self.row.refresh_from_db()
        self.assertIsNone(self.row.consumed_at)

    def test_an_audit_failure_rolls_the_account_back(self) -> None:
        from apps.audit.services import AuditService  # noqa: PLC0415

        real = AuditService.log_simple_event

        def failing(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("event_type", args[0] if args else None) == "terms_of_service_accepted":
                raise RuntimeError("audit store unavailable")
            return real(*args, **kwargs)

        with patch.object(AuditService, "log_simple_event", side_effect=failing), self.assertRaises(RuntimeError):
            self.accept(self.terms)
        self.assertFalse(User.objects.filter(email=self.row.email).exists())
        self.assertFalse(Customer.objects.filter(company_name="Terms en SRL").exists())
        self.assertFalse(CustomerMembership.objects.exists())
        # The link was not spent: the same confirmation succeeds once the audit store is back.
        self.assertTrue(self.accept(self.terms).is_ok())

    # --- API ------------------------------------------------------------------------------------

    def post_confirm(self, **overrides: Any) -> Any:
        body = {
            "registration_id": str(self.row.pk),
            "token": self.row.token(),
            "password": NEW_PASSPHRASE,
            "password_confirm": NEW_PASSPHRASE,
            **overrides,
        }
        return self.portal_post("/api/users/register/confirm/", body)

    def preview_api(self) -> Any:
        return self.portal_post(
            "/api/users/register/pending/", {"registration_id": str(self.row.pk), "token": self.row.token()}
        )

    def test_the_api_previews_and_records_the_release(self) -> None:
        self.assertEqual(self.preview_api().json()["registration"]["terms_document"], self.terms.reference())
        response = self.post_confirm(terms_accepted=True, terms_document_id=str(self.terms.pk))
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(User.objects.get(email=self.row.email).terms_document, self.terms)

    def test_the_api_answers_missing_acceptance_or_release_on_the_field(self) -> None:
        for body, field in (({}, "terms_accepted"), ({"terms_accepted": True}, "terms_document_id")):
            with self.subTest(field):
                response = self.post_confirm(**body)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertIn(field, response.json()["errors"])
        self.assertFalse(User.objects.filter(email=self.row.email).exists())

    def test_the_api_answers_a_superseded_or_missing_release_with_its_own_code(self) -> None:
        response = self.post_confirm(terms_accepted=True, terms_document_id=str(self.row.pk))  # not a release
        self.assertEqual((response.status_code, response.json()["code"]), (409, "terms_changed"))
        with patch("apps.users.registration_confirmation.current_legal_document", return_value=None):
            response = self.post_confirm(terms_accepted=True, terms_document_id=str(self.terms.pk))
            preview = self.preview_api()
        for answer in (response, preview):
            self.assertEqual((answer.status_code, answer.json()["code"]), (409, "terms_unavailable"))

    # --- GDPR -----------------------------------------------------------------------------------

    def test_the_export_includes_acceptance_and_anonymisation_clears_it(self) -> None:
        self.assertTrue(self.accept(self.terms).is_ok())
        user = User.objects.get(email=self.row.email)
        profile = GDPRExportService._collect_user_data(user, {"include_profile": True})["user_profile"]
        self.assertEqual(profile["terms_document"], self.terms.reference())
        self.assertEqual(profile["terms_accepted_at"], user.terms_accepted_at.isoformat())
        self.assertTrue(GDPRDeletionService._anonymize_user_data(user).is_ok())
        user.refresh_from_db()
        self.assertIsNone(user.terms_accepted_at)
        self.assertIsNone(user.terms_document)
