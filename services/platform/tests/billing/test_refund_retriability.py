"""
Retriability annotations on RefundService lookup failures.

Only genuinely transient database failures (connection drops, deadlocks —
OperationalError/InterfaceError) may assert RETRIABLE. The broad
except-Exception catch-all must stay UNKNOWN: a malformed id raises the
same exception on every attempt, and labeling it RETRIABLE is exactly the
"most dangerous wrong answer" the tri-state design exists to prevent.
"""

from unittest.mock import patch

from django.db import InterfaceError, OperationalError
from django.test import SimpleTestCase, TestCase

from apps.billing.refund_service import RefundData, RefundService
from apps.common.types import Err, Retriability


def _patched_order_manager(side_effect: Exception):
    return patch(
        "apps.billing.refund_service.Order.objects.select_for_update",
        side_effect=side_effect,
    )


class RefundLookupRetriabilityTests(SimpleTestCase):
    def test_unexpected_exception_is_unknown(self) -> None:
        with _patched_order_manager(RuntimeError("malformed id")):
            result = RefundService._get_order("not-a-real-id")

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)

    def test_operational_error_is_retriable(self) -> None:
        with _patched_order_manager(OperationalError("deadlock detected")):
            result = RefundService._get_order("some-id")

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_interface_error_is_retriable(self) -> None:
        with _patched_order_manager(InterfaceError("connection already closed")):
            result = RefundService._get_order("some-id")

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_invoice_lookup_mirrors_order_semantics(self) -> None:
        with patch(
            "apps.billing.refund_service.Invoice.objects.select_for_update",
            side_effect=RuntimeError("malformed id"),
        ):
            result = RefundService._get_invoice("not-a-real-id")

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)


class RefundLivePathRetriabilityTests(TestCase):
    """The RETRIABLE signal must reach the LIVE entry points (refund_order/refund_invoice),
    not just the _get_order/_get_invoice helpers (PR #255 review P2).

    Uses TestCase (real DB) so transaction.atomic() rolls the mocked deadlock back and
    re-raises the OperationalError the outer handler classifies.
    """

    def test_refund_order_surfaces_transient_db_error_as_retriable(self) -> None:
        with patch(
            "apps.billing.refund_service.Order.objects.select_for_update",
            side_effect=OperationalError("deadlock detected"),
        ):
            result = RefundService.refund_order("some-id", RefundData(amount_cents=100, reason="x"))

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_refund_invoice_surfaces_transient_db_error_as_retriable(self) -> None:
        with patch(
            "apps.billing.refund_service.Invoice.objects.select_for_update",
            side_effect=InterfaceError("connection already closed"),
        ):
            result = RefundService.refund_invoice("some-id", RefundData(amount_cents=100, reason="x"))

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)
