"""What a refund's correction credits is decided by the ledger as it stood when the refund completed.

The worker may run long after the refund: a payment arriving meanwhile, a dispute, or the invoice
becoming paid must not change the answer. Payments count from when they succeeded, whatever their
status is now; the paid floor applies only if the invoice was paid by then; and the refunds already
taken off are those of the corrections ordered before this one, by the same key the worker uses.
"""

from __future__ import annotations

from datetime import timedelta

from django.utils import timezone

from apps.billing.fiscal_correction_models import FiscalCorrection
from apps.billing.models import Invoice, Payment, Refund
from tests.billing._storno_helpers import SELLER, StornoTestCase


@SELLER
class AmountOwedAsOfCompletionTests(StornoTestCase):
    def test_a_payment_arriving_after_the_refund_does_not_cancel_its_credit(self) -> None:
        """Invoice 100, collected 100, refund 20; then 20 more arrives before the worker runs.
        Read now, collections are 120 and the refund looks like an overpayment being returned; as
        of the refund, nothing was overpaid and 20 is owed."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 10000)
        correction = self.refund(original, payment, 2000)
        Payment.objects.create(
            customer=original.customer,
            invoice=original,
            currency=original.currency,
            status="succeeded",
            payment_method="bank_transfer",
            amount_cents=2000,
        )

        self.assertEqual(self.process(correction).total_cents, -2000)

    def test_a_payment_pending_at_the_refund_counts_from_when_it_succeeded(self) -> None:
        """Received (reserved) before the refund but only succeeded after it: not yet held."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 10000)
        late = Payment.objects.create(
            customer=original.customer,
            invoice=original,
            currency=original.currency,
            payment_method="bank_transfer",
            amount_cents=2000,
            received_at=timezone.now() - timedelta(days=1),
        )
        correction = self.refund(original, payment, 2000)
        late.succeed()
        # Saved the way the payment services save a transition, writing the status alone.
        late.save(update_fields=["status", "updated_at"])

        self.assertEqual(self.process(correction).total_cents, -2000)

    def test_a_payment_without_a_success_time_counts_from_when_it_was_received(self) -> None:
        """Rows written already succeeded (imports, bank transfers) carry no success time; their
        receipt time stands in. Received before the refund, 120 was held, so 20 returns slack."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 12000)
        Payment.objects.filter(pk=payment.pk).update(succeeded_at=None)

        self.assertEqual(self.process(self.refund(original, payment, 2000)).state, "not_required")

    def test_a_refund_without_a_completion_time_is_ordered_by_its_creation(self) -> None:
        """An earlier refund whose completion time was never written still counts as earlier."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 12000)
        earlier = self.refund(original, payment, 2000)
        Refund.objects.filter(pk=earlier.source_refund_id).update(processed_at=None)
        later = self.refund(original, payment, 3000)

        self.process(earlier)
        # Held before the later refund: 120 - 20 = 100 against 100 owed, so all 30 is credited.
        self.assertEqual(self.process(later).total_cents, -3000)

    def test_a_dispute_after_the_refund_does_not_change_what_was_held(self) -> None:
        """Invoice 100, 120 collected, 20 refunded: the overpayment going back, nothing to credit.
        The payment is disputed before the worker runs; as of the refund it was still held."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 12000)
        correction = self.refund(original, payment, 2000)
        payment.refresh_from_db()
        payment.dispute_payment()
        payment.save(update_fields=["status", "updated_at"])

        decided = self.process(correction)

        self.assertEqual(decided.state, "not_required")
        self.assertIsNone(decided.total_cents)

    def test_a_payment_disputed_while_pending_never_counts(self) -> None:
        """No success time and a status that was never collected: it may never have succeeded."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 10000)
        never = Payment.objects.create(
            customer=original.customer,
            invoice=original,
            currency=original.currency,
            payment_method="bank_transfer",
            amount_cents=2000,
            received_at=timezone.now() - timedelta(days=1),
        )
        never.dispute_payment()
        never.save(update_fields=["status", "updated_at"])

        self.assertEqual(self.process(self.refund(original, payment, 2000)).total_cents, -2000)

    def test_the_paid_floor_applies_only_if_the_invoice_was_paid_by_the_refund(self) -> None:
        """Invoice 100 already credited 30 by a note no refund backs; 40 collected, 10 refunded.
        It is paid in full only afterwards. As of the refund, 40 was held against 70 still owed, so
        all 10 is credited; flooring at the total because it is paid NOW would read 30 of slack."""
        original = self.original(lines=((10000, "0.00"),))
        Invoice.objects.create(
            customer=original.customer,
            currency=original.currency,
            document_kind="credit_note",
            reverses_invoice=original,
            subtotal_cents=-3000,
            tax_cents=0,
            total_cents=-3000,
        )
        payment = self.collected(original, 4000, mark_paid=False)
        correction = self.refund(original, payment, 1000)
        self.collected(original, 7000, mark_paid=False)
        original.refresh_from_db()
        original.mark_as_paid()
        original.save(update_fields=["status", "paid_at"])

        self.assertEqual(self.process(correction).total_cents, -1000)

    def test_refunds_sharing_a_timestamp_are_ordered_like_their_corrections(self) -> None:
        """120 collected against 100; refunds of 20 then 30 completing at the same instant. The
        worker orders their corrections by (completion, creation, id); what each one subtracts as
        already returned must follow the same order, or the second credits 10 instead of 30."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 12000)
        first = self.refund(original, payment, 2000)
        second = self.refund(original, payment, 3000)
        Refund.objects.filter(pk__in=[first.source_refund_id, second.source_refund_id]).update(
            processed_at=timezone.now()
        )

        self.assertEqual(self.process(first).state, "not_required")
        self.assertEqual(self.process(second).total_cents, -3000)

    def test_reversed_creation_order_still_credits_each_refund_once(self) -> None:
        """The same two refunds, the 30 recorded first: it takes the 20 of slack and credits 10, the
        20 then credits 20. Together they credit the 30 that went beyond the overpayment."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 12000)
        first = self.refund(original, payment, 3000)
        second = self.refund(original, payment, 2000)
        Refund.objects.filter(pk__in=[first.source_refund_id, second.source_refund_id]).update(
            processed_at=timezone.now()
        )

        credited = [self.process(first).total_cents, self.process(second).total_cents]

        self.assertEqual(credited, [-1000, -2000])

    def test_a_refund_with_no_correction_on_the_invoice_is_still_taken_off(self) -> None:
        """A refund completed while its invoice was a draft is recorded not-required with no original,
        yet 20 went back. A later refund of 30 against 120 collected for 100 must count that 20 as
        already returned, or it reads 20 of slack that no longer exists and credits 10."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 12000)
        draft_era = self.refund(original, payment, 2000)
        refund_id = draft_era.source_refund_id
        FiscalCorrection.objects.filter(pk=draft_era.pk).delete()
        FiscalCorrection.objects.create(
            source_refund_id=refund_id, state="not_required", not_required_reason="no_fiscal_document"
        )

        self.assertEqual(self.process(self.refund(original, payment, 3000)).total_cents, -3000)
