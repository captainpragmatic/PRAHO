"""A credit note is a correction, and the declaration has to be able to say so.

Two sign guards rejected a reversal outright: the header check read
`discount_cents > gross` as `0 > -10000`, and the per-line check rejected any
`subtotal_cents <= 0`. So every reversal became a review exception carrying a wrong
diagnostic, while the partner's declared base kept the full original amount.

The policy is to net into the current period. `d390.py` refuses to serialise a
non-positive base, and `_group_supplies` already raises `zero_rounded_base` for a
partner whose month nets to zero or below — so the one case that genuinely cannot be
filed was always reported honestly. These guards are what stopped a reversal reaching
that point at all.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.billing.ec_sales_service import (
    _discount_allocations,
    _document_problems,
    _line_problems,
)
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, Currency, Invoice
from tests.factories.billing_factories import CustomerFactory


class _StubLine:
    """Every attribute the two guards actually read, and nothing else."""

    def __init__(
        self,
        subtotal_cents: int,
        tax_cents: int = 0,
        line_total_cents: int | None = None,
    ) -> None:
        self.pk = abs(subtotal_cents) or 1
        self.quantity = Decimal("1")
        self.unit_price_cents = subtotal_cents
        self.subtotal_cents = subtotal_cents
        self.tax_cents = tax_cents
        self.line_total_cents = subtotal_cents if line_total_cents is None else line_total_cents
        self.tax_rate = Decimal("0")
        self.tax_category_code = "AE"
        self.kind = "service"
        self.discount_amount_cents = 0


class DiscountAllocationSignTests(SimpleTestCase):
    """Allocation was reported as sign-broken; it is not. Pinning that it stays so.

    Floor division rounds towards negative infinity in both directions, so it
    over-allocates either way and the correcting slice bound stays positive. Worth a
    test because the reasoning is not obvious from reading it.
    """

    def test_a_positive_discount_allocates_to_the_cent(self) -> None:
        lines = [_StubLine(3333), _StubLine(3334), _StubLine(3335)]

        self.assertEqual(sum(_discount_allocations(lines, 100).values()), 100)

    def test_a_negative_discount_allocates_to_the_cent_too(self) -> None:
        lines = [_StubLine(-3333), _StubLine(-3334), _StubLine(-3335)]

        allocated = _discount_allocations(lines, -100)

        self.assertEqual(sum(allocated.values()), -100, f"every cent must land: {allocated}")
        for pk, value in allocated.items():
            self.assertLessEqual(value, 0, f"line {pk} got a positive share of a credit")

    def test_no_discount_allocates_nothing(self) -> None:
        self.assertEqual(sum(_discount_allocations([_StubLine(-3333)], 0).values()), 0)


class LineSignGuardTests(SimpleTestCase):
    """A negated line is a correction, not a malformed supply."""

    def test_a_reverse_charge_supply_is_accepted(self) -> None:
        self.assertEqual(_line_problems(_StubLine(10000)), [])

    def test_its_reversal_is_accepted_too(self) -> None:
        self.assertEqual(
            _line_problems(_StubLine(-10000)),
            [],
            "a negated line is the correction, not a malformed supply",
        )

    def test_a_zero_line_is_still_rejected(self) -> None:
        """The regression guard: relaxing the sign must not accept an empty line."""
        self.assertNotEqual(_line_problems(_StubLine(0)), [])


class DocumentSignGuardTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "L", "decimals": 2}
        )[0]
        self._seq = 0

    def _reversal(self, *, subtotal: int, discount: int, line_gross: int) -> tuple[Invoice, list[_StubLine]]:
        self._seq += 1
        original = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"EC-ORIG-{self._seq}",
            status="draft",
            issued_at=timezone.now(),
            locked_at=timezone.now(),
            tax_point_date=timezone.now().date(),
            subtotal_cents=abs(subtotal),
            tax_cents=0,
            total_cents=abs(subtotal),
            discount_cents=abs(discount),
            bill_to_name="Partner GmbH",
            bill_to_country="DE",
        )
        credit_note = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"EC-CN-{self._seq}",
            status="draft",
            issued_at=timezone.now(),
            locked_at=timezone.now(),
            tax_point_date=timezone.now().date(),
            subtotal_cents=subtotal,
            tax_cents=0,
            total_cents=subtotal,
            discount_cents=discount,
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            bill_to_name="Partner GmbH",
            bill_to_country="DE",
        )
        return credit_note, [_StubLine(line_gross)]

    def test_a_reversal_does_not_report_a_totals_mismatch(self) -> None:
        credit_note, lines = self._reversal(subtotal=-9000, discount=-1000, line_gross=-10000)

        problems = " ".join(_document_problems(credit_note, lines, None))

        self.assertNotIn("totals_mismatch", problems, f"the reversal reconciles; got {problems}")

    def test_a_genuine_mismatch_is_still_reported(self) -> None:
        """The regression guard: relaxing the sign must not accept an unbalanced document."""
        credit_note, lines = self._reversal(subtotal=-9000, discount=-1000, line_gross=-12345)

        problems = " ".join(_document_problems(credit_note, lines, None))

        self.assertIn("totals_mismatch", problems)
