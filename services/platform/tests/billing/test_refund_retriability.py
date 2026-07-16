"""
Retriability of RefundService failures.

The refund flow is GATEWAY-FIRST and non-idempotent: it calls the external
payment gateway to refund the customer BEFORE the local DB writes (see
_process_payment_refund, "GATEWAY-FIRST"). So a transient DB failure anywhere
in that flow may occur AFTER the customer was already refunded — replaying it
would double-refund. Therefore NO refund failure may assert RETRIABLE; the
whole service fails closed at the UNKNOWN default. (Caught by the #261 bot
review; my earlier instinct to mark transient DB errors RETRIABLE was unsafe.)
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
    """The lookup helpers must never assert RETRIABLE — they feed the gateway-first flow."""

    def test_unexpected_exception_is_unknown(self) -> None:
        with _patched_order_manager(RuntimeError("malformed id")):
            result = RefundService._get_order("not-a-real-id")

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)

    def test_transient_db_error_is_not_retriable(self) -> None:
        """A deadlock/dropped-connection on the lookup stays UNKNOWN: replay of the
        gateway-first, non-idempotent refund flow could double-refund the customer."""
        for exc in (OperationalError("deadlock detected"), InterfaceError("connection already closed")):
            with self.subTest(exc=type(exc).__name__), _patched_order_manager(exc):
                result = RefundService._get_order("some-id")
                assert isinstance(result, Err)
                self.assertEqual(result.retriability, Retriability.UNKNOWN)

    def test_invoice_lookup_mirrors_order_semantics(self) -> None:
        with patch(
            "apps.billing.refund_service.Invoice.objects.select_for_update",
            side_effect=OperationalError("deadlock"),
        ):
            result = RefundService._get_invoice("some-id")

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)


class RefundLivePathRetriabilityTests(TestCase):
    """The live entry points must fail closed (UNKNOWN) on a transient DB error, never
    RETRIABLE — a retry after a gateway-first refund could issue a second refund.

    Uses TestCase (real DB) so transaction.atomic() rolls the mocked deadlock back.
    """

    def test_refund_order_transient_db_error_is_not_retriable(self) -> None:
        with patch(
            "apps.billing.refund_service.Order.objects.select_for_update",
            side_effect=OperationalError("deadlock detected"),
        ):
            result = RefundService.refund_order("some-id", RefundData(amount_cents=100, reason="x"))

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)

    def test_refund_invoice_transient_db_error_is_not_retriable(self) -> None:
        with patch(
            "apps.billing.refund_service.Invoice.objects.select_for_update",
            side_effect=InterfaceError("connection already closed"),
        ):
            result = RefundService.refund_invoice("some-id", RefundData(amount_cents=100, reason="x"))

        assert isinstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)
