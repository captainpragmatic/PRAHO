"""#220/#286 follow-through: service-period DateFields derive from the ROMANIAN calendar day.

InvoiceLine/ProformaLine period_start/period_end are plain DateFields emitted VERBATIM into
the e-Factura XML as InvoicePeriod (BT-134/135) — the builder deliberately does not convert
them (#287). The Romanian day must therefore be fixed at the derivation sites: raw .date()
on an aware UTC datetime yields the previous day for anything created between 00:00 and
02:00/03:00 Romanian time, putting a wrong legal period into the ANAF filing and
contradicting the (now RO-correct) IssueDate of the same document.
"""

from datetime import UTC, date, datetime
from decimal import Decimal

from django.test import TestCase

from apps.billing.invoice_models import InvoiceSequence
from apps.billing.models import Currency, ProformaInvoice
from apps.billing.proforma_models import ProformaSequence
from apps.billing.proforma_service import ProformaService
from apps.billing.views import _process_proforma_line_items
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from tests.helpers.fsm_helpers import force_status


class PeriodDatesRomanianLocalTests(TestCase):
    """Both period-derivation sites roll to the Romanian day in the midnight window."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Period TZ SRL",
            customer_type="company",
            status="active",
            primary_email="period-tz@test.ro",
            company_name="Period TZ SRL",
        )
        ProformaSequence.objects.get_or_create(scope="default")
        InvoiceSequence.objects.get_or_create(scope="default")

    def test_proforma_from_order_period_bounds_use_romanian_dates(self) -> None:
        """An order placed 2026-01-15 22:30 UTC is already 2026-01-16 in Romania: the
        service period must start on the 16th (and end 30 days on, also RO-local), not on
        the UTC 15th — which would contradict the invoice's own IssueDate."""
        product = Product.objects.create(
            name="Shared Hosting Basic",
            slug="period-tz-hosting",
            product_type="shared_hosting",
            is_active=True,
        )
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={"company_name": "Period TZ SRL", "country": "RO"},
        )
        OrderItem.objects.create(
            order=order,
            product=product,
            product_name=product.name,
            product_type=product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        force_status(order, "awaiting_payment")
        Order.objects.filter(pk=order.pk).update(created_at=datetime(2026, 1, 15, 22, 30, tzinfo=UTC))
        order.refresh_from_db()

        proforma = ProformaService.create_from_order(order).unwrap()

        line = proforma.lines.first()
        self.assertEqual(line.period_start, date(2026, 1, 16))
        # Default billing period is 30 days: 2026-01-15 22:30 UTC + 30d = 2026-02-14 22:30 UTC,
        # which is already 2026-02-15 in Romania.
        self.assertEqual(line.period_end, date(2026, 2, 15))

    def test_manual_proforma_line_period_bounds_use_romanian_dates(self) -> None:
        """The staff proforma line editor derives period_start from the proforma's creation
        instant — across New Year the UTC day is not just wrong, it is in the wrong YEAR.

        period_end is assigned the raw aware valid_until and relies on Django's DateField
        coercion, which casts through the default timezone before truncating (BT-135): a
        controlled near-midnight valid_until pins that behavior as a repo-owned guarantee
        rather than a reading of Django internals.
        """
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number="PRO-PERIOD-TZ",
            currency=self.currency,
            valid_until=datetime(2026, 1, 30, 22, 30, tzinfo=UTC),
            subtotal_cents=0,
            tax_cents=0,
            total_cents=0,
        )
        ProformaInvoice.objects.filter(pk=proforma.pk).update(
            created_at=datetime(2025, 12, 31, 22, 30, tzinfo=UTC)
        )
        proforma.refresh_from_db()

        errors = _process_proforma_line_items(
            proforma,
            {
                "line_0_description": "Web Hosting",
                "line_0_quantity": "1",
                "line_0_unit_price": "100",
                "line_0_vat_rate": "21",
            },
        )

        self.assertEqual(errors, [])
        line = proforma.lines.first()
        self.assertEqual(line.period_start, date(2026, 1, 1))
        # 2026-01-30 22:30 UTC is already 2026-01-31 in Romania.
        self.assertEqual(line.period_end, date(2026, 1, 31))
