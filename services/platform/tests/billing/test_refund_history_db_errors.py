"""How a failed refund status-history write is classified (#548).

The history write tolerates a database error as a logged audit-trail gap, but it names
``DatabaseError`` alone on purpose. ``InterfaceError`` is not tolerated: it reaches the
record's transient handler and comes back as a retriable ``Err``.

An ``Err`` must also mean nothing was written. The reservation paths call the helper
inside their own ``transaction.atomic(durable=True)`` and return the ``Err`` normally,
which COMMITS whatever the helper wrote, so a ``Refund`` row created before the failed
history write used to survive as an orphaned pending intent the caller was told had
failed. The tests below go through the real reservation callers and assert that no
partial write survives.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from django.db import DatabaseError, InterfaceError
from django.test import TestCase

from apps.billing.models import Payment, Refund, RefundStatusHistory
from apps.billing.refund_service import RefundData, RefundRecordParams, RefundResult, RefundService
from apps.common.types import Err, Result, Retriability
from tests.billing.test_refund_service_regressions import (
    _make_bank_payment,
    _make_currency,
    _make_customer,
    _make_invoice,
    _make_order,
)

_HISTORY_CREATE = "apps.billing.refund_service.RefundStatusHistory.objects.create"


class RefundHistoryDatabaseErrorTests(TestCase):
    def _create_with_history_failure(self, exc: Exception) -> Result[Refund, str]:
        order = _make_order(_make_customer(), _make_currency(), status="completed", total_cents=10000)
        params = RefundRecordParams(
            refund_id=uuid.uuid4(),
            order=order,
            invoice=None,
            refund_amount_cents=5000,
            original_cents=10000,
            refund_data=None,
        )
        with patch(_HISTORY_CREATE, side_effect=exc):
            return RefundService._create_refund_record(params)

    def test_database_error_is_a_logged_audit_gap(self) -> None:
        result = self._create_with_history_failure(DatabaseError("history insert failed"))
        self.assertTrue(result.is_ok())
        self.assertEqual(Refund.objects.count(), 1)
        self.assertEqual(RefundStatusHistory.objects.count(), 0)

    def test_interface_error_fails_the_record_retriably(self) -> None:
        result = self._create_with_history_failure(InterfaceError("connection already closed"))
        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)
        # The helper's Err leaves nothing behind, whatever transaction the caller holds.
        self.assertEqual(Refund.objects.count(), 0)


class RefundReservationLeavesNoPartialWriteTests(TestCase):
    """Through the real reservation callers: an Err must leave no Refund row behind."""

    def setUp(self) -> None:
        self.customer = _make_customer()
        self.currency = _make_currency()

    def _assert_nothing_written(self, result: Result[RefundResult, str], payment: Payment) -> None:
        self.assertTrue(result.is_err())
        self.assertEqual(Refund.objects.count(), 0)
        self.assertEqual(RefundStatusHistory.objects.count(), 0)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")

    def test_refund_invoice_history_interface_error_writes_nothing(self) -> None:
        invoice = _make_invoice(self.customer, self.currency, status="paid", total_cents=10000)
        payment = _make_bank_payment(self.customer, self.currency, invoice=invoice)
        data: RefundData = {"amount_cents": 10000, "refund_type": "full", "reason": "customer_request"}

        with patch(_HISTORY_CREATE, side_effect=InterfaceError("connection already closed")):
            result = RefundService.refund_invoice(invoice.id, data)

        self._assert_nothing_written(result, payment)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid")

    def test_refund_order_history_interface_error_writes_nothing(self) -> None:
        order = _make_order(self.customer, self.currency, status="completed", total_cents=10000)
        payment = _make_bank_payment(self.customer, self.currency, order=order)
        data: RefundData = {"amount_cents": 10000, "refund_type": "full", "reason": "customer_request"}

        with patch(_HISTORY_CREATE, side_effect=InterfaceError("connection already closed")):
            result = RefundService.refund_order(order.id, data)

        self._assert_nothing_written(result, payment)
        order.refresh_from_db()
        self.assertEqual(order.status, "completed")
