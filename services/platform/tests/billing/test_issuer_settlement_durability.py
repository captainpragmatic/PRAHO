"""Confirmed fiscal issuance survives settlement failures."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.db import DatabaseError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditAlert
from apps.billing.issuers import service
from apps.billing.issuers.base import Issued
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.metering_models import BillingCycle
from apps.billing.models import Currency, Invoice, Payment
from apps.billing.subscription_models import Subscription
from apps.common.types import Result
from apps.products.models import Product
from tests.factories.billing_factories import CustomerFactory


class IssuedDocumentSettlementTests(TestCase):
    def setUp(self) -> None:
        for target in ("django_q.tasks.async_task", "apps.notifications.services.EmailService.send_template_email"):
            quiet = patch(target, return_value="test-delivery")
            quiet.start()
            self.addCleanup(quiet.stop)
        self.customer = CustomerFactory()
        self.currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=0,
            total_cents=10000,
            bill_to_name="Settlement test",
            bill_to_country="DE",
            issuer_provider="smartbill",
        )
        self.token = uuid4()
        self.issuance = ProviderIssuance.objects.create(
            invoice=self.invoice,
            provider="smartbill",
            state=IssuanceState.CLAIMED.value,
            claim_token=self.token,
            claim_expires_at=timezone.now() + timedelta(minutes=10),
            attempts=1,
        )

    def confirm(self) -> Result[str, str]:
        return service._finalize(
            self.invoice.pk,
            self.issuance.pk,
            self.token,
            Issued(series="FCT", number="000123", provider_document_id="20363", response_digest="confirmed"),
        )

    def reconcile(self) -> Result[str, str]:
        return service.reconcile_confirmed_issued(
            self.issuance.pk, series="FCT", number="000123", operator_note="Found in provider UI"
        )

    def quarantine(self) -> None:
        self.issuance.mark_outcome_unknown(reason="Response lost")
        self.issuance.save()

    def fund(self) -> Payment:
        payment = Payment(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="other",
        )
        payment._defer_document_settlement = True
        payment.succeed()
        payment.save()
        return payment

    def cancelled_renewal(self) -> tuple[Subscription, BillingCycle]:
        now = timezone.now()
        product = Product.objects.create(name="Hosting", slug="settlement-hosting", product_type="shared_hosting")
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=product,
            currency=self.currency,
            status="active",
            unit_price_cents=10000,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            next_billing_date=now,
            cancel_at_period_end=True,
        )
        cycle = BillingCycle.objects.create(
            subscription=subscription,
            invoice=self.invoice,
            period_start=now,
            period_end=now + timedelta(days=30),
            collection_status="processing",
        )
        return subscription, cycle

    def assert_issued_with_failure(self, reason: str) -> None:
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.number, "FCT-000123")
        self.assertEqual(self.invoice.status, "issued")
        self.assertIsNone(self.invoice.paid_at)
        issuance = ProviderIssuance.objects.get(pk=self.issuance.pk)
        self.assertEqual(issuance.state, IssuanceState.ISSUED.value)
        self.assertEqual((issuance.provider_series, issuance.provider_number), ("FCT", "000123"))
        self.assertIsNone(issuance.claim_token)
        self.assertIsNone(issuance.claim_expires_at)
        alert = AuditAlert.objects.get(
            metadata={"source": "provider_issuance_settlement", "invoice_id": self.invoice.pk}
        )
        self.assertEqual((alert.status, alert.severity), ("active", "high"))
        self.assertEqual(alert.evidence["invoice_number"], "FCT-000123")
        self.assertIn(reason, alert.evidence["error"])

    def test_confirmed_issuance_survives_convergence_err_and_can_recover(self) -> None:
        payment = self.fund()
        subscription, cycle = self.cancelled_renewal()
        with self.captureOnCommitCallbacks(execute=True):
            result = self.confirm()
        self.assert_issued_with_failure("no longer permits renewal entitlement")
        self.assertTrue(result.is_ok(), str(result))
        issuance = ProviderIssuance.objects.get(pk=self.issuance.pk)
        self.assertEqual(issuance.provider_document_id, "20363")
        self.assertEqual(issuance.response, {"digest": "confirmed"})
        self.assertEqual(issuance.submissions, 1)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "succeeded")
        cycle.refresh_from_db()
        self.assertIsNone(cycle.entitlement_applied_at)
        self.assertEqual(cycle.collection_status, "processing")

        subscription.cancel_at_period_end = False
        subscription.save(update_fields=["cancel_at_period_end"])
        with self.captureOnCommitCallbacks(execute=True):
            service._settle_issued_document(self.invoice.pk)
        self.invoice.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertIsNotNone(cycle.entitlement_applied_at)
        self.assertEqual(cycle.collection_status, "paid")
        self.assertEqual(ProviderIssuance.objects.get(pk=self.issuance.pk).submissions, 1)
        self.assertEqual(Payment.objects.filter(invoice=self.invoice).count(), 1)

    def test_reconciliation_survives_convergence_err(self) -> None:
        payment = self.fund()
        self.cancelled_renewal()
        self.quarantine()
        with self.captureOnCommitCallbacks(execute=True):
            result = self.reconcile()
        self.assert_issued_with_failure("no longer permits renewal entitlement")
        self.assertTrue(result.is_ok(), str(result))
        issuance = ProviderIssuance.objects.get(pk=self.issuance.pk)
        self.assertIn("Found in provider UI", issuance.last_error)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "succeeded")

    def assert_zero_total_paid(self, *, reconciled: bool) -> None:
        self.invoice.subtotal_cents = 0
        self.invoice.total_cents = 0
        self.invoice.save(update_fields=["subtotal_cents", "total_cents"])
        if reconciled:
            self.quarantine()
        activated: list[Invoice] = []
        with (
            patch("apps.billing.signals._trigger_virtualmin_provisioning_on_payment", side_effect=activated.append),
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = self.reconcile() if reconciled else self.confirm()
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertTrue(result.is_ok(), str(result))
        self.assertEqual(self.invoice.number, "FCT-000123")
        self.assertIsNotNone(self.invoice.paid_at)
        self.assertFalse(Payment.objects.filter(invoice=self.invoice).exists())
        self.assertEqual([invoice.pk for invoice in activated], [self.invoice.pk])

    def test_zero_total_issuance_runs_paid_lifecycle_without_payment(self) -> None:
        self.assert_zero_total_paid(reconciled=False)

    def test_zero_total_reconciliation_runs_paid_lifecycle_without_payment(self) -> None:
        self.assert_zero_total_paid(reconciled=True)

    def test_reconciliation_defers_settlement_until_caller_commits(self) -> None:
        self.fund()
        self.quarantine()
        with self.captureOnCommitCallbacks(execute=True), transaction.atomic():
            result = self.reconcile()
            self.invoice.refresh_from_db()
            self.assertEqual(self.invoice.status, "issued")
            self.assertIsNone(self.invoice.paid_at)
            self.customer.company_name = "Operator attribution committed"
            self.customer.save(update_fields=["company_name"])
        self.assertTrue(result.is_ok(), str(result))
        self.invoice.refresh_from_db()
        self.customer.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertEqual(self.customer.company_name, "Operator attribution committed")

    def test_settlement_database_exception_preserves_confirmed_issuance(self) -> None:
        self.fund()
        with (
            patch.object(Invoice, "update_status_from_payments", side_effect=DatabaseError("Settlement unavailable")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = self.confirm()
        self.assert_issued_with_failure("Settlement unavailable")
        self.assertTrue(result.is_ok(), str(result))
