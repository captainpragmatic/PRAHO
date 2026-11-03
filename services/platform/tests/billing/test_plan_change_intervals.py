"""Quotes use proven paid intervals and fixed obligations rather than future pointers."""

from datetime import timedelta
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.billing.models import BillingCycle, Invoice, InvoiceLine, Payment, ProformaInvoice, ProformaLine
from apps.billing.plan_change_coverage import load_plan_coverage
from apps.billing.plan_change_models import PlanChangeInterval
from apps.billing.plan_change_pricing import quote_supplements
from apps.billing.proforma_service import ProformaPaymentService
from tests.billing.test_plan_change_models import _PlanChangeFixture


class _PlanChangeCoverageFixture(_PlanChangeFixture):
    def cycle(self, *, start=None, end=None, paid=True, amount=8000):
        cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=start or self.subscription.current_period_start,
            period_end=end or self.subscription.current_period_end,
            status="active",
            collection_status="paid" if paid else "prepared",
        )
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PC-{uuid4().hex}",
            subtotal_cents=amount,
            total_cents=amount,
        )
        line = InvoiceLine.objects.create(
            invoice=invoice,
            service=self.service,
            billing_cycle=cycle,
            kind="service",
            description="Frozen fixed hosting",
            quantity=1,
            unit_price_cents=amount,
            period_start=cycle.period_start.date(),
            period_end=cycle.period_end.date(),
        )
        invoice.issue()
        invoice.save()
        if paid:
            Payment.objects.create(
                customer=self.customer,
                invoice=invoice,
                currency=self.currency,
                amount_cents=amount,
                status="succeeded",
                payment_method="bank",
            )
            invoice.mark_as_paid()
            invoice.save(update_fields=["status", "paid_at"])
        cycle.invoice = invoice
        cycle.base_charge_cents = amount
        cycle.save(update_fields=["invoice", "base_charge_cents"])
        return cycle, invoice, line


class PlanChangeCoverageTests(_PlanChangeCoverageFixture, TestCase):
    def test_frozen_base_identity_survives_real_renewal_payment_and_conversion(self) -> None:
        current, _, _ = self.cycle()
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"BASE-{uuid4().hex}",
            subtotal_cents=8000,
            total_cents=8000,
            valid_until=self.now + timedelta(days=30),
            bill_to_country="RO",
        )
        future = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=current.period_end,
            period_end=current.period_end + timedelta(days=30),
            status="active",
            collection_status="prepared",
            proforma=proforma,
        )
        ProformaLine.objects.create(
            proforma=proforma,
            service=self.service,
            billing_cycle=future,
            kind="service",
            description="Original fixed future period",
            quantity=1,
            unit_price_cents=8000,
            period_start=future.period_start.date(),
            period_end=future.period_end.date(),
        )
        proforma.send_proforma()
        proforma.save(update_fields=["status"])
        before = load_plan_coverage(self.subscription, at=self.now).evidence[str(future.pk)]
        paid = ProformaPaymentService.record_payment_and_convert(str(proforma.pk), 8000, "bank")
        self.assertTrue(paid.is_ok(), paid)
        self.subscription.refresh_from_db()
        after = load_plan_coverage(self.subscription, at=self.now)
        self.assertEqual(after.evidence[str(future.pk)], before)
        self.assertTrue(after.intervals[1].paid)

    def test_early_paid_renewal_pointers_do_not_change_current_proration(self) -> None:
        current, _, _ = self.cycle()
        future, _, _ = self.cycle(start=current.period_end, end=current.period_end + timedelta(days=30))
        self.subscription.current_period_start = future.period_start
        self.subscription.current_period_end = future.period_end
        self.subscription.save(update_fields=["current_period_start", "current_period_end"])
        coverage = load_plan_coverage(self.subscription, at=self.now)
        self.assertEqual(coverage.current_period_price_cents, 8000)
        self.assertEqual([item.evidence_id for item in coverage.intervals], [str(current.pk), str(future.pk)])
        parts = quote_supplements(
            intervals=coverage.intervals,
            quoted_at=self.now,
            current_period_price_cents=coverage.current_period_price_cents,
            target_period_price_cents=20000,
        )
        self.assertEqual([item.net_cents for item in parts], [6000, 12000])

    def test_issued_unpaid_future_is_a_protected_base_obligation(self) -> None:
        current, _, _ = self.cycle()
        self.cycle(start=current.period_end, end=current.period_end + timedelta(days=30), paid=False)
        coverage = load_plan_coverage(self.subscription, at=self.now)
        self.assertEqual([item.paid for item in coverage.intervals], [True, False])
        self.assertEqual([item.base_net_cents for item in coverage.intervals], [8000, 8000])

    def test_dispute_invalidates_current_coverage_before_any_review_worker(self) -> None:
        _, invoice, _ = self.cycle()
        payment = invoice.payments.get()
        payment.dispute_payment()
        payment.save(update_fields=["status"])
        with self.assertRaisesRegex(ValidationError, "coverage|disput"):
            load_plan_coverage(self.subscription, at=self.now)

    def test_waived_unknown_current_cycle_does_not_manufacture_paid_evidence(self) -> None:
        BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=self.subscription.current_period_start,
            period_end=self.subscription.current_period_end,
            status="active",
            collection_status="waived",
        )
        with self.assertRaises(ValidationError):
            load_plan_coverage(self.subscription, at=self.now)

    def test_duplicate_fixed_line_and_retargeted_service_are_refused(self) -> None:
        cycle, invoice, line = self.cycle()
        InvoiceLine.objects.filter(pk=line.pk).update(service=None)
        with self.assertRaises(ValidationError):
            load_plan_coverage(self.subscription, at=self.now)
        InvoiceLine.objects.filter(pk=line.pk).update(service=self.service)
        # Normal document guards prevent creating ambiguous evidence at its source.
        with self.assertRaises(ValidationError):
            InvoiceLine.objects.bulk_create(
                [
                    InvoiceLine(
                        invoice=invoice,
                        service=self.service,
                        billing_cycle=cycle,
                        kind="service",
                        description="duplicate fixed evidence",
                        quantity=1,
                        unit_price_cents=8000,
                    )
                ]
            )
        self.assertEqual(load_plan_coverage(self.subscription, at=self.now).current_period_price_cents, 8000)

    def test_settled_supplement_is_counted_once_and_sets_effective_current_tariff(self) -> None:
        current, _, _ = self.cycle()
        future, _, _ = self.cycle(start=current.period_end, end=current.period_end + timedelta(days=30))
        change = self.change(net_cents=18000, tax_cents=0, total_cents=18000)
        document = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"TOPUP-{uuid4().hex}",
            subtotal_cents=18000,
            total_cents=18000,
        )
        InvoiceLine.objects.create(
            invoice=document,
            service=self.service,
            kind="service",
            description="Plan supplements",
            quantity=1,
            unit_price_cents=18000,
        )
        document.issue()
        document.save()
        Payment.objects.create(
            customer=self.customer,
            invoice=document,
            currency=self.currency,
            amount_cents=18000,
            status="succeeded",
            payment_method="bank",
        )
        document.mark_as_paid()
        document.save(update_fields=["status", "paid_at"])
        for ordinal, cycle in enumerate((current, future)):
            PlanChangeInterval.objects.create(
                change=change,
                ordinal=ordinal,
                period_start=cycle.period_start,
                period_end=cycle.period_end,
                slice_start=self.now if ordinal == 0 else cycle.period_start,
                base_net_cents=8000,
                prior_supplement_cents=0,
                net_cents=6000 if ordinal == 0 else 12000,
                current_slice=ordinal == 0,
                evidence={"cycle_id": str(cycle.pk)},
            )
        change.invoice = document
        change.committed_at = self.now
        change.confirm()
        change.commit_limits()
        change.save(update_fields=["invoice", "committed_at", "status"])
        coverage = load_plan_coverage(self.subscription, at=self.now)
        self.assertEqual(coverage.current_period_price_cents, 20000)
        self.assertEqual([item.settled_supplement_cents for item in coverage.intervals], [6000, 12000])
        parts = quote_supplements(
            intervals=coverage.intervals,
            quoted_at=self.now,
            current_period_price_cents=coverage.current_period_price_cents,
            target_period_price_cents=30000,
        )
        self.assertEqual([item.net_cents for item in parts], [5000, 10000])
        document.payments.get().dispute_payment()  # In-memory change alone is not evidence.
        self.assertEqual(load_plan_coverage(self.subscription, at=self.now).current_period_price_cents, 20000)
        payment = document.payments.get()
        payment.dispute_payment()
        payment.save(update_fields=["status"])
        with self.assertRaises(ValidationError):
            load_plan_coverage(self.subscription, at=self.now)
