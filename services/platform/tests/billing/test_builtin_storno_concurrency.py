"""PostgreSQL proof that two workers on one correction issue one credit note and spend one number.

The queued task and the hourly sweep can both reach the same correction. The first holds the
correction's row lock from issuance until its commit; the second must wait on that lock, then find
the note already issued and stop, before it locks the original or consults anything else. SQLite has
no row locks, so this is only observable here.
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase

from apps.billing import fiscal_correction_worker
from apps.billing.fiscal_correction_models import STATE_ISSUED, FiscalCorrection
from apps.billing.invoice_models import ISSUER_BUILTIN, SEQUENCE_SCOPE_DEFAULT, Invoice, InvoiceLine, InvoiceSequence
from apps.billing.numbering_service import InvoiceNumberingService
from tests.billing import _fiscal_correction_helpers as h

WORKER_LOGGER = "apps.billing.fiscal_correction_worker"


def _finished_within(future: Any, *, seconds: float) -> bool:
    try:
        future.result(timeout=seconds)
    except TimeoutError:
        return False
    return True


class BuiltinStornoPostgresConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock waits require PostgreSQL")
        owner = h.customer()
        self.original = Invoice.objects.create(
            customer=owner,
            currency=h.ron(),
            number=InvoiceNumberingService.get_next_number(),
            sequence_scope=SEQUENCE_SCOPE_DEFAULT,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            issuer_provider=ISSUER_BUILTIN,
            bill_to_name="Customer SRL",
            bill_to_country="DE",
        )
        InvoiceLine.objects.bulk_create(
            [
                InvoiceLine(
                    invoice=self.original,
                    kind="service",
                    description="Hosting",
                    quantity=1,
                    unit_price_cents=10000,
                    tax_rate="0.21",
                    tax_cents=2100,
                    line_total_cents=12100,
                )
            ]
        )
        self.original.issue()
        self.original.save()
        payment = h.paid(self.original)
        refund = h.pending_refund(
            invoice=self.original,
            payment=payment,
            amount_cents=1000,
            refund_type="partial",
            reference_number=f"REF-{uuid.uuid4().hex[:12]}",
        )
        h.complete(refund)
        self.correction = FiscalCorrection.objects.get(source_refund_id=refund.pk)

    @staticmethod
    def _work(correction_id: str) -> None:
        close_old_connections()
        try:
            fiscal_correction_worker.process_fiscal_correction(correction_id)
        finally:
            connection.close()

    def test_two_workers_on_one_correction_issue_one_note_and_spend_one_number(self) -> None:
        before = InvoiceSequence.objects.get(scope="default").last_value
        first_issuing = threading.Event()
        release_first = threading.Event()
        call_lock = threading.Lock()
        calls = 0
        real_issue = fiscal_correction_worker._issue_credit_note

        def parking_issue(correction: FiscalCorrection, original: Invoice) -> Invoice:
            """Hold the first worker inside its issuing transaction, its note numbered, uncommitted."""
            nonlocal calls
            note = real_issue(correction, original)
            with call_lock:
                calls += 1
                call_number = calls
            if call_number == 1:
                first_issuing.set()
                if not release_first.wait(timeout=10):
                    raise AssertionError("timed out releasing the first worker")
            return note

        with (
            patch.object(fiscal_correction_worker, "_issue_credit_note", parking_issue),
            patch.object(fiscal_correction_worker, "_send_credit_note_email", return_value=(True, "")),
            self.assertNoLogs(WORKER_LOGGER, level="ERROR"),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(self._work, str(self.correction.pk))
            self.assertTrue(first_issuing.wait(timeout=10), "the first worker never reached issuance")
            second = executor.submit(self._work, str(self.correction.pk))
            second_waited = not _finished_within(second, seconds=1)
            release_first.set()
            first.result(timeout=15)
            second.result(timeout=15)

        self.assertTrue(second_waited, "the second worker did not wait on the first worker's lock")
        self.assertEqual(calls, 1, "the second worker must not have issued at all")
        self.assertEqual(Invoice.objects.filter(reverses_invoice=self.original).count(), 1)
        self.assertEqual(InvoiceSequence.objects.get(scope="default").last_value, before + 1)
        correction = FiscalCorrection.objects.get(pk=self.correction.pk)
        self.assertIn(correction.state, {STATE_ISSUED, "communicated"})
        self.assertEqual(correction.total_cents, -1000)


class StornoCommunicationPostgresConcurrencyTests(TransactionTestCase):
    """Two senders racing the one email that dates a note: the claim commits first, so one sends."""

    reset_sequences = True

    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock waits require PostgreSQL")
        BuiltinStornoPostgresConcurrencyTests.setUp(self)
        with patch.object(fiscal_correction_worker, "_send_credit_note_email", return_value=(False, "SMTP down")):
            fiscal_correction_worker.process_fiscal_correction(str(self.correction.pk))
        self.assertEqual(FiscalCorrection.objects.get(pk=self.correction.pk).state, STATE_ISSUED)

    @staticmethod
    def _deliver(correction_id: str) -> None:
        close_old_connections()
        try:
            fiscal_correction_worker.deliver_credit_note(correction_id)
        finally:
            connection.close()

    def test_two_concurrent_senders_send_one_email(self) -> None:
        first_sending = threading.Event()
        release_first = threading.Event()
        sends = 0
        sends_lock = threading.Lock()

        def slow_send(note: Invoice) -> tuple[bool, str]:
            nonlocal sends
            with sends_lock:
                sends += 1
            first_sending.set()
            if not release_first.wait(timeout=10):
                raise AssertionError("timed out releasing the first sender")
            return True, ""

        with (
            patch.object(fiscal_correction_worker, "_send_credit_note_email", side_effect=slow_send),
            self.assertNoLogs(WORKER_LOGGER, level="ERROR"),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(self._deliver, str(self.correction.pk))
            self.assertTrue(first_sending.wait(timeout=10), "the first sender never started sending")
            second = executor.submit(self._deliver, str(self.correction.pk))
            second.result(timeout=15)
            release_first.set()
            first.result(timeout=15)

        self.assertEqual(sends, 1, "the second sender must see the committed claim and not send")
        correction = FiscalCorrection.objects.get(pk=self.correction.pk)
        self.assertEqual(correction.state, "communicated")
        self.assertIsNone(correction.communication_claimed_at)
