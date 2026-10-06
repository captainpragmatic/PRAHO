"""Portal overdue flags retain Platform authority and its instant-based fallback."""

from datetime import UTC, datetime
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.utils import timezone

from apps.billing.serializers import create_invoice_from_api


def _invoice_payload(*, status: str = "issued", due_at: str | None = "2026-10-05T23:59:59+03:00") -> dict[str, object]:
    return {
        "id": 101,
        "number": "INV-OVERDUE",
        "status": status,
        "total_cents": 12100,
        "amount_due": 0 if status == "paid" else 12100,
        "currency": {"id": 1, "code": "RON", "name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        "due_at": due_at,
        "created_at": "2026-10-01T09:00:00Z",
    }


@override_settings(USE_TZ=True, TIME_ZONE="Europe/Bucharest")
class InvoiceOverdueTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(timezone.override("Europe/Bucharest"))
        self.enterContext(patch("django.utils.timezone.now", return_value=datetime(2026, 10, 5, 22, 30, tzinfo=UTC)))

    def test_platform_flag_is_used_at_the_local_midnight_boundary(self) -> None:
        payload = _invoice_payload()
        payload["is_overdue"] = True
        invoice = create_invoice_from_api(payload)

        self.assertEqual(timezone.localtime().isoformat(), "2026-10-06T01:30:00+03:00")
        self.assertEqual(invoice.is_overdue, payload["is_overdue"])

    def test_missing_flag_compares_instants_including_naive_datetimes(self) -> None:
        cases = (
            ("2026-10-05T23:59:59+03:00", True),
            ("2026-10-06T01:29:59+03:00", True),
            ("2026-10-06T01:30:00+03:00", False),
            ("2026-10-06T01:30:01+03:00", False),
            ("2026-10-05T23:59:59", True),
            (None, False),
        )
        for due_at, expected in cases:
            with self.subTest(due_at=due_at):
                invoice = create_invoice_from_api(_invoice_payload(due_at=due_at))
                self.assertEqual(invoice.is_overdue, expected)

    def test_present_flags_override_the_portal_clock_in_both_directions(self) -> None:
        cases = (
            ("2026-10-04T23:59:59+03:00", False),
            ("2026-10-06T23:59:59+03:00", True),
        )
        for due_at, platform_flag in cases:
            with self.subTest(due_at=due_at, platform_flag=platform_flag):
                payload = _invoice_payload(due_at=due_at)
                payload["is_overdue"] = platform_flag
                invoice = create_invoice_from_api(payload)

                self.assertEqual(invoice.is_overdue, platform_flag)

    def test_only_issued_invoices_are_overdue_and_paid_invoices_stay_clear(self) -> None:
        for status in ("issued", "paid", "draft", "overdue", "partially_paid", "cancelled", "void", "refunded"):
            with self.subTest(status=status, flag="absent"):
                invoice = create_invoice_from_api(
                    _invoice_payload(status=status, due_at="2026-10-04T23:59:59+03:00")
                )
                self.assertEqual(invoice.is_overdue, status == "issued")
            if status != "issued":
                with self.subTest(status=status, flag=False):
                    payload = _invoice_payload(status=status, due_at="2026-10-04T23:59:59+03:00")
                    payload["is_overdue"] = False
                    self.assertFalse(create_invoice_from_api(payload).is_overdue)
