"""Final-review findings on the built-in storno worker, each pinned by the test it failed.

1. The amount owed is read from the ledger as it stood when the refund completed, not when the
   worker happens to run.
2. Another worker's upload still in flight is not an ANAF registration.
3. Corrections of one original issue in refund-completion order, so the parked one is the later.
4. An allocation cannot hold a timestamp without its amounts (SQL NULL passes a bare `<= 0`).
5. The e-Factura backoff cannot overflow before its cap.
6. The worker is queued only after settlement commits, never before and never after a rollback.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.db import IntegrityError, transaction
from django.test import override_settings
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus
from apps.billing.efactura.service import SubmissionResult
from apps.billing.fiscal_correction_models import (
    EFACTURA_PENDING,
    EFACTURA_SUBMITTED,
    FAILURE_SECOND_CREDIT_NOTE,
    STATE_ALLOCATED,
    STATE_FAILED,
    FiscalCorrection,
)
from apps.billing.fiscal_correction_worker import (
    EFACTURA_MAX_BACKOFF,
    TASK_PATH,
    _advance_allocation,
    _advance_efactura,
    _advance_issuance,
    efactura_backoff,
)
from apps.billing.models import Payment, Refund
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


@SELLER
@override_settings(EFACTURA_ENABLED=True)
class InFlightUploadTests(StornoTestCase):
    def test_another_workers_live_upload_is_not_recorded_as_submitted(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        correction = self.process(self.refund(original, payment, 1000))
        EFacturaDocument.objects.create(
            invoice=original, document_type=EFacturaDocumentType.INVOICE.value, environment="test"
        )
        EFacturaDocument.objects.filter(invoice=original).update(status=EFacturaStatus.ACCEPTED.value)
        uploading = EFacturaDocument(status=EFacturaStatus.UPLOADING.value)
        FiscalCorrection.objects.filter(pk=correction.pk).update(
            efactura_status=EFACTURA_PENDING, efactura_next_attempt_at=None
        )

        with patch(
            "apps.billing.efactura.service.EFacturaService.submit_invoice",
            return_value=SubmissionResult.ok(uploading),
        ):
            _advance_efactura(str(correction.pk))

        correction.refresh_from_db()
        self.assertNotEqual(correction.efactura_status, EFACTURA_SUBMITTED)
        self.assertEqual(correction.efactura_status, EFACTURA_PENDING)
        self.assertIsNotNone(correction.efactura_next_attempt_at)


@SELLER
class IssuanceOrderTests(StornoTestCase):
    def test_a_later_correction_cannot_issue_before_an_earlier_one(self) -> None:
        """Both allocated; the later worker reaches issuance first. It must wait, so the earlier
        correction takes the one note A2 allows and the later is the one parked."""
        original = self.original()
        payment = self.collected(original, original.total_cents)
        earlier = self.refund(original, payment, 3000)
        later = self.refund(original, payment, 2000)
        _advance_allocation(str(earlier.pk))
        _advance_allocation(str(later.pk))

        with self.captureOnCommitCallbacks(execute=True):
            later_first = _advance_issuance(str(later.pk))
            earlier_next = _advance_issuance(str(earlier.pk))
            later_again = _advance_issuance(str(later.pk))

        earlier.refresh_from_db()
        later.refresh_from_db()
        self.assertEqual((later_first, earlier_next, later_again), ("waiting_for_earlier", "issued", "parked"))
        self.assertEqual(earlier.credit_note.total_cents, -3000)
        self.assertEqual((later.state, later.failure_code), (STATE_FAILED, FAILURE_SECOND_CREDIT_NOTE))


class AllocationNullAmountTests(StornoTestCase):
    def test_an_allocation_timestamp_without_its_amounts_is_refused(self) -> None:
        original = self.original()
        correction = self.refund(original, self.collected(original, original.total_cents), 1000)

        with self.assertRaises(IntegrityError), transaction.atomic():
            FiscalCorrection.objects.filter(pk=correction.pk).update(
                state=STATE_FAILED, allocated_at=timezone.now(), vat_residue_cents=0
            )
        self.assertNotEqual(FiscalCorrection.objects.get(pk=correction.pk).state, STATE_ALLOCATED)


class BackoffCapTests(StornoTestCase):
    def test_a_long_failing_filing_backs_off_a_week_without_overflowing(self) -> None:
        self.assertEqual(efactura_backoff(100), EFACTURA_MAX_BACKOFF)
        self.assertEqual(efactura_backoff(10_000), timedelta(days=7))
        self.assertEqual(efactura_backoff(1), timedelta(hours=1))


class QueueAfterCommitTests(StornoTestCase):
    def test_the_worker_is_queued_only_after_commit_and_never_after_a_rollback(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)

        def worker_calls(queued: Any) -> list[Any]:
            return [call for call in queued.call_args_list if call.args[0] == TASK_PATH]

        with patch("django_q.tasks.async_task") as queued:
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                correction = self.refund(original, payment, 1000)
            self.assertEqual(worker_calls(queued), [], "queued before settlement committed")
            for callback in callbacks:
                callback()
            self.assertEqual([call.args[1] for call in worker_calls(queued)], [str(correction.pk)])

            queued.reset_mock()
            with self.captureOnCommitCallbacks(execute=True):
                try:
                    with transaction.atomic():
                        self.refund(original, payment, 500)
                        raise RuntimeError("settlement rolled back")
                except RuntimeError:
                    pass
            self.assertEqual(worker_calls(queued), [], "queued for a refund whose settlement rolled back")
