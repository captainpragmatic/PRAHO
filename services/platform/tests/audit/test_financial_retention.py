"""Financial evidence is kept 5 years from 1 July of the year after its financial year.

Legea contabilității 82/1991 art. 25, as amended by Legea 36/2023 (in force 2023-01-15). A record
drawn up in 2026 is kept until 2032-07-01, so the rule is a calendar cutoff in Romanian time, not
a day count: a January record needs 6.5 years, a December one 5.5. Retention (delete and
anonymise) and full GDPR erasure all hold such evidence until then (ADR-0043).
"""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from apps.audit.management.commands.setup_audit_retention_policies import RETENTION_POLICY_SEED
from apps.audit.models import AuditEvent, AuditRetentionPolicy, audit_mutation_allowed
from apps.audit.services import AuditRetentionService, GDPRDeletionService
from apps.billing.invoice_models import Invoice
from apps.promotions.models import Coupon, GiftCard

User = get_user_model()
BUCHAREST = ZoneInfo("Europe/Bucharest")


def local(*args: int) -> datetime:
    return datetime(*args, tzinfo=BUCHAREST)


class FinancialRetentionCutoffTests(TestCase):
    def test_a_2026_record_is_kept_until_1_july_2032(self) -> None:
        cutoff = AuditRetentionService.financial_retention_cutoff
        self.assertEqual(cutoff(local(2032, 6, 30, 23, 59)), local(2026, 1, 1))
        self.assertEqual(cutoff(local(2032, 7, 1, 0, 0)), local(2027, 1, 1))

    def test_the_cutoff_is_computed_in_romanian_time_whatever_the_active_zone(self) -> None:
        # 2032-06-30 22:30 UTC is already 1 July in Bucharest.
        utc_instant = datetime(2032, 6, 30, 22, 30, tzinfo=ZoneInfo("UTC"))
        with timezone.override("America/New_York"):
            self.assertEqual(AuditRetentionService.financial_retention_cutoff(utc_instant), local(2027, 1, 1))

    def test_a_late_december_utc_event_belongs_to_the_next_romanian_year(self) -> None:
        event = AuditEvent(action="invoice_issued", category="business_operation")
        event.timestamp = datetime(2026, 12, 31, 22, 30, tzinfo=ZoneInfo("UTC"))  # 2027-01-01 in Bucharest
        self.assertTrue(AuditRetentionService.is_held(event, local(2032, 7, 1)))
        self.assertFalse(AuditRetentionService.is_held(event, local(2033, 7, 1)))


class RetentionHoldTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="retention@example.test", password="pass12345")
        self.content_type = ContentType.objects.get_for_model(User)

    def event(self, action: str, category: str, when: datetime, **fields: object) -> AuditEvent:
        event = AuditEvent.objects.create(
            user=self.user,
            action=action,
            category=category,
            severity="low",
            content_type=fields.pop("content_type", self.content_type),
            object_id=str(self.user.pk),
            description=f"{action} evidence",
            new_values={"amount_cents": 12100},
            metadata={},
            **fields,
        )
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(timestamp=when)
        return event

    def policy(self, category: str, days: int, action: str = "delete") -> None:
        AuditRetentionPolicy.objects.create(
            name=f"{category} {action}", category=category, retention_days=days, action=action, is_active=True
        )

    def test_a_financial_event_is_held_past_its_policy_until_the_legal_date(self) -> None:
        event = self.event("invoice_issued", "integration", local(2026, 3, 1))
        self.policy("integration", 30)

        AuditRetentionService.apply_retention_policies(now=local(2032, 6, 30, 12))
        self.assertTrue(AuditEvent.objects.filter(pk=event.pk).exists())

        AuditRetentionService.apply_retention_policies(now=local(2032, 7, 1, 12))
        self.assertFalse(AuditEvent.objects.filter(pk=event.pk).exists())

    def test_vat_validation_evidence_outlives_the_compliance_policy(self) -> None:
        event = self.event("vat_validation_completed", "compliance", local(2026, 3, 1))
        self.policy("compliance", 1096)

        AuditRetentionService.apply_retention_policies(now=local(2030, 1, 1, 12))

        self.assertTrue(AuditEvent.objects.filter(pk=event.pk).exists())

    def test_the_business_policy_keeps_every_event_past_any_legal_date(self) -> None:
        [business] = [seed for seed in RETENTION_POLICY_SEED if seed["category"] == "business_operation"]
        self.assertGreaterEqual(business["retention_days"], 2374)
        # An event name nobody classified, from January 2026, is still there on its latest legal date.
        event = self.event("unlisted_billing_event", "business_operation", local(2026, 1, 2))
        self.policy("business_operation", business["retention_days"])

        AuditRetentionService.apply_retention_policies(now=local(2032, 6, 30, 12))

        self.assertTrue(AuditEvent.objects.filter(pk=event.pk).exists())

    def test_anonymisation_does_not_blank_held_evidence(self) -> None:
        event = self.event("refund_processed", "privacy", local(2026, 3, 1))
        self.policy("privacy", 30, action="anonymize")

        AuditRetentionService.apply_retention_policies(now=local(2030, 1, 1, 12))

        event.refresh_from_db()
        self.assertEqual(event.description, "refund_processed evidence")
        self.assertEqual(event.new_values, {"amount_cents": 12100})

    def test_full_erasure_keeps_held_evidence_with_its_content(self) -> None:
        held = self.event("invoice_issued", "business_operation", timezone.now(), ip_address="198.51.100.7")
        login = self.event("login_success", "authentication", timezone.now())
        # A business event that is not financial evidence is the person's data, not a legal record.
        profile_edit = self.event("profile_updated", "business_operation", timezone.now())
        request = GDPRDeletionService.create_deletion_request(user=self.user, deletion_type="delete").unwrap()

        self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())

        self.assertFalse(User.objects.filter(email="retention@example.test").exists())
        self.assertFalse(AuditEvent.objects.filter(pk=login.pk).exists())
        self.assertFalse(AuditEvent.objects.filter(pk=profile_edit.pk).exists())
        held.refresh_from_db()
        self.assertIsNone(held.user)
        self.assertNotEqual(held.ip_address, "198.51.100.7")
        self.assertEqual(held.description, "invoice_issued evidence")
        self.assertEqual(held.new_values, {"amount_cents": 12100})


class FinancialClassifierTests(TestCase):
    def classify(self, action: str, model: type | None = None) -> bool:
        content_type = ContentType.objects.get_for_model(model or User)
        return AuditRetentionService._is_financial_record(
            AuditEvent(action=action, category="business_operation", content_type=content_type, object_id="1")
        )

    def test_financial_events_emitted_by_billing_orders_and_promotions(self) -> None:
        for action in (
            "refund_processed",
            "refund_model_deleted",
            "order_refund",
            "order_payment_failed",
            "fiscal_correction_created",
            "recurring_payment_submission_deleted",
            "subscription_payment_failed",
            "usage_invoice_created",
            "vat_validation_completed",
            "provider_issuance_deleted",
            "currency_conversion_applied",
            "tax_rule_applied",
            "credit_ledger_deleted",
            "invoice_issued",
            "payment_gateway_refund",
            "efactura_submitted",
        ):
            with self.subTest(action=action):
                self.assertTrue(self.classify(action))

    def test_generic_events_about_billing_records_and_money_ledgers_are_financial(self) -> None:
        self.assertTrue(self.classify("update", Invoice))
        self.assertTrue(self.classify("delete", GiftCard))
        self.assertFalse(self.classify("update", Coupon))
        self.assertFalse(self.classify("login_success"))
        self.assertFalse(self.classify("random_action"))
