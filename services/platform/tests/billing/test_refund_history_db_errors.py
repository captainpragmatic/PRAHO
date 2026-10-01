"""How a failed refund status-history write is classified (#548).

The history write tolerates a database error as a logged audit-trail gap, but it names
``DatabaseError`` alone on purpose. ``InterfaceError`` means the connection is unusable,
so the refund row cannot commit either: it has to reach the record's own transient
handler and come back as a retriable ``Err``, not be swallowed into an ``Ok`` for a
refund that will never persist.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from django.db import DatabaseError, InterfaceError
from django.test import TestCase

from apps.billing.models import Refund, RefundStatusHistory
from apps.billing.refund_service import RefundRecordParams, RefundService
from apps.common.types import Err, Result, Retriability
from tests.billing.test_refund_service_regressions import _make_currency, _make_customer, _make_order


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
        with patch("apps.billing.refund_service.RefundStatusHistory.objects.create", side_effect=exc):
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
