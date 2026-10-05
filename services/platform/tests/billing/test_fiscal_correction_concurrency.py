"""PostgreSQL proof of the two guarantees the completion hook makes under real transactions.

1. Two legs of one tender command completing at the same time record ONE correction. Each leg's
   hook looks first, finds nothing (the other's insert is uncommitted), and inserts; only the
   unique source link and `get_or_create`'s retry make the loser converge on the winner's row.
2. A database error inside the recording never costs the refund its settlement. On PostgreSQL an
   error swallowed without its own savepoint aborts the whole transaction, so this is only
   observable here; SQLite carries on regardless.
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import MagicMock, patch

from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase

from apps.billing.fiscal_correction_models import FiscalCorrection
from apps.billing.models import Payment, Refund
from apps.billing.refund_service import RefundService
from apps.promotions.models import TenderRefundCommand, TenderRefundLeg
from tests.billing import _fiscal_correction_helpers as h

HOOK_LOGGER = "apps.billing.signals"


class FiscalCorrectionPostgresConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("unique-index waits and aborted transactions require PostgreSQL")
        self.owner = h.customer()
        self.invoice = h.issued_invoice(self.owner)

    def _approved_legs(self) -> list[Refund]:
        """Two legs of one command, each refund approved and one step from completing."""
        cash = h.paid(self.invoice, amount_cents=7100)
        transfer = Payment.objects.create(
            customer=self.owner,
            invoice=self.invoice,
            currency=self.invoice.currency,
            status="succeeded",
            payment_method="bank_transfer",
            amount_cents=5000,
        )
        command = TenderRefundCommand.objects.create(
            invoice=self.invoice,
            customer=self.owner,
            amount_cents=self.invoice.total_cents,
            operation_key=f"fiscal-race-{uuid.uuid4().hex[:8]}",
            reason="test",
        )
        refunds = []
        for payment in (cash, transfer):
            refund = h.pending_refund(invoice=self.invoice, payment=payment, amount_cents=payment.amount_cents)
            TenderRefundLeg.objects.create(
                command=command, payment=payment, refund=refund, amount_cents=refund.amount_cents
            )
            refund.start_processing()
            refund.save(update_fields=["status", "updated_at"])
            refund.approve()
            refund.save(update_fields=["status", "updated_at"])
            refunds.append(refund)
        self.command = command
        return refunds

    @staticmethod
    def _complete_in_own_transaction(refund_pk: uuid.UUID) -> None:
        close_old_connections()
        try:
            with transaction.atomic():
                refund = Refund.objects.select_for_update().get(pk=refund_pk)
                result = RefundService._advance_refund_status(refund, "succeeded")
                if result.is_err():
                    raise AssertionError(result.unwrap_err())
        finally:
            connection.close()

    def test_two_legs_completing_together_record_one_correction(self) -> None:
        first_leg, second_leg = self._approved_legs()
        first_inserted = threading.Event()
        release_first = threading.Event()
        call_lock = threading.Lock()
        calls = 0
        original_save = FiscalCorrection.save

        def parking_save(instance: FiscalCorrection, *args: Any, **kwargs: Any) -> None:
            """Hold the first leg's transaction open just after its insert, before it commits."""
            nonlocal calls
            with call_lock:
                calls += 1
                call_number = calls
            original_save(instance, *args, **kwargs)
            if call_number == 1:
                first_inserted.set()
                if not release_first.wait(timeout=10):
                    raise AssertionError("timed out releasing the first leg")

        with (
            patch.object(FiscalCorrection, "save", parking_save),
            self.assertNoLogs(HOOK_LOGGER, level="ERROR"),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(self._complete_in_own_transaction, first_leg.pk)
            self.assertTrue(first_inserted.wait(timeout=10), "the first leg never recorded its correction")
            second = executor.submit(self._complete_in_own_transaction, second_leg.pk)
            # Unique, the second leg's insert waits on the first's uncommitted row.
            second_waited = not _finished_within(second, seconds=1)
            release_first.set()
            first.result(timeout=15)
            second.result(timeout=15)

        self.assertTrue(second_waited, "the second leg did not wait on the first leg's insert")
        self.assertEqual(Refund.objects.filter(pk__in=[first_leg.pk, second_leg.pk], status="completed").count(), 2)
        correction = FiscalCorrection.objects.get()
        self.assertEqual(correction.source_command_id, self.command.pk)
        self.assertEqual(correction.original_id, self.invoice.pk)

    def test_a_database_error_while_recording_never_aborts_settlement(self) -> None:
        payment = h.paid(self.invoice)
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_fiscal_pg_abort",
            "amount_refunded_cents": self.invoice.total_cents,
            "status": "succeeded",
            "error": None,
        }

        def poisoning_record(refund: Refund) -> None:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM fiscal_correction_table_that_does_not_exist")

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
            patch("apps.billing.fiscal_correction_service.record_obligation", side_effect=poisoning_record),
            self.assertLogs(HOOK_LOGGER, level="ERROR") as logs,
        ):
            result = RefundService.refund_invoice(
                self.invoice.pk,
                {"refund_type": "full", "amount_cents": self.invoice.total_cents, "reason": "customer_request"},
            )

        self.assertTrue(result.is_ok(), result)
        refund = Refund.objects.get(invoice=self.invoice)
        self.assertEqual(refund.status, "completed")
        self.invoice.refresh_from_db()
        payment.refresh_from_db()
        self.assertEqual(self.invoice.status, "refunded")
        self.assertEqual(payment.status, "refunded")
        self.assertFalse(FiscalCorrection.objects.exists())
        self.assertTrue(any(str(refund.pk) in line for line in logs.output), logs.output)


def _finished_within(future: Any, *, seconds: float) -> bool:
    try:
        future.result(timeout=seconds)
    except TimeoutError:
        return False
    return True
