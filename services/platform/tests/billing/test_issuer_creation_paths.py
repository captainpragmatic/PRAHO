"""Every path that creates an invoice must honour the configured issuer.

The issuer decision was made in exactly one of the creation services. The others
kept allocating a PRAHO number inline, so selecting SmartBill silently left those
documents numbered by PRAHO's own fiscal sequence — a legal act under an authority
the operator did not choose, frozen permanently on the document.

And a reversal that cannot be enqueued must still be recoverable: the refund has
already moved money, so losing the correction leaves the customer holding a full
invoice with nothing reversing it.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
    InvoiceSequence,
)
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.tasks import sweep_owed_reversals
from apps.billing.refund_models import Refund
from apps.billing.services import InvoiceService
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.settings.services import SettingsService
from config.settings.test import LOCMEM_TEST_CACHE
from tests.factories.billing_factories import CustomerFactory
from tests.helpers.fsm_helpers import force_status


def _select_smartbill() -> None:
    result = SettingsService.update_setting("billing.invoice_issuer", ISSUER_SMARTBILL, reason="test")
    if result.is_err():  # pragma: no cover - a failure here invalidates the test
        raise AssertionError(f"could not select SmartBill: {result.error}")


class OrderPathHonoursTheIssuerTests(TestCase):
    def setUp(self) -> None:
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        self.customer = Customer.objects.create(
            name="Order Co",
            customer_type="company",
            company_name="Order Co",
            status="active",
            primary_email="order@example.com",
        )
        self.product = Product.objects.create(
            name="Shared Hosting",
            slug="hosting-issuer",
            product_type="shared_hosting",
            is_active=True,
        )
        InvoiceSequence.objects.get_or_create(scope="default")

    def _order(self) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            billing_address={"company_name": "Order Co", "country": "RO"},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=2,
            unit_price_cents=5000,
            tax_rate=Decimal("0.1900"),
            tax_cents=1900,
            line_total_cents=11900,
        )
        return order

    def test_the_builtin_issuer_still_numbers_inline(self) -> None:
        """The default path must be unchanged: this is the regression guard."""
        result = InvoiceService().create_from_order(self._order())

        self.assertTrue(result.is_ok(), result)
        invoice = result.unwrap()
        self.assertEqual(invoice.issuer_provider, ISSUER_BUILTIN)
        self.assertIsNotNone(invoice.number)

    def test_an_external_issuer_defers_the_number_instead_of_minting_one(self) -> None:
        _select_smartbill()

        result = InvoiceService().create_from_order(self._order())

        self.assertTrue(result.is_ok(), result)
        invoice = result.unwrap()
        self.assertEqual(
            invoice.issuer_provider,
            ISSUER_SMARTBILL,
            "provenance is frozen at creation; stamping builtin here is permanent",
        )
        self.assertIsNone(
            invoice.number,
            "PRAHO must not consume its own fiscal sequence for a document it is not issuing",
        )

    def test_an_external_issuer_leaves_a_row_for_the_issuance_to_resume_from(self) -> None:
        _select_smartbill()

        invoice = InvoiceService().create_from_order(self._order()).unwrap()

        issuance = ProviderIssuance.objects.filter(invoice=invoice).first()
        self.assertIsNotNone(issuance, "without this row the sweep cannot recover a lost enqueue")
        assert issuance is not None
        self.assertEqual(issuance.state, IssuanceState.PENDING.value)
        self.assertEqual(issuance.provider, ISSUER_SMARTBILL)


class OwedReversalIsRecoverableTests(TransactionTestCase):
    """A queue outage at refund time must not lose the correction."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _refunded_provider_invoice(self) -> Invoice:
        self._seq = getattr(self, "_seq", 0) + 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FCT-00090{self._seq}",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.ISSUED.value,
            provider_series="FCT",
            provider_number=f"00090{self._seq}",
        )
        force_status(invoice, "paid")
        force_status(invoice, "refunded")
        Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            status="completed",
            refund_type="full",
            amount_cents=12100,
            currency=self.currency,
            original_amount_cents=12100,
            reference_number=f"REF-OWED-{invoice.pk}",
        )
        return invoice

    def _split_refunded_invoice(self) -> Invoice:
        """Refunded in two instalments: eligibility refuses this one permanently."""
        invoice = self._refunded_provider_invoice()
        Refund.objects.filter(invoice=invoice).delete()
        for index, amount in enumerate((4000, 8100)):
            Refund.objects.create(
                customer=self.customer,
                invoice=invoice,
                status="completed",
                refund_type="partial",
                amount_cents=amount,
                currency=self.currency,
                original_amount_cents=12100,
                reference_number=f"REF-SPLIT-{invoice.pk}-{index}",
            )
        return invoice

    def test_a_reversal_whose_enqueue_failed_is_found_again(self) -> None:
        # The refund settles while the queue is unavailable. The signal resolves
        # `queue_invoice_storno` from the module at call time, so this is the real
        # boundary; patching `async_task` would miss it (it is a function-level
        # import, so the module attribute is never consulted).
        with patch("apps.billing.issuers.tasks.queue_invoice_storno", return_value=None):
            invoice = self._refunded_provider_invoice()

        self.assertFalse(
            Invoice.objects.filter(reverses_invoice=invoice).exists(),
            "precondition: the enqueue failed, so no reversal was produced",
        )

        queued: list[int] = []
        with patch(
            "apps.billing.issuers.tasks.queue_invoice_storno",
            side_effect=lambda pk: queued.append(pk) or "task-id",
        ):
            report = sweep_owed_reversals()

        self.assertEqual(queued, [invoice.pk], "the owed reversal must be picked up again")
        self.assertEqual(report["queued"], 1)

    def test_an_invoice_already_reversed_is_not_swept_again(self) -> None:
        invoice = self._refunded_provider_invoice()
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=invoice,
            issuer_provider=ISSUER_SMARTBILL,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )

        queued: list[int] = []
        with patch(
            "apps.billing.issuers.tasks.queue_invoice_storno",
            side_effect=lambda pk: queued.append(pk) or "task-id",
        ):
            sweep_owed_reversals()

        self.assertEqual(queued, [], "a reversal that exists is already owned by its own claim")

    @override_settings(CACHES=LOCMEM_TEST_CACHE)
    def test_permanently_refused_invoices_do_not_starve_the_queue(self) -> None:
        """A refusal that can never succeed must not monopolise every sweep.

        An invoice refunded in instalments is refused forever, and stays refunded
        with no reversal - so it stays a candidate forever. Taking the first N
        candidates by primary key means the oldest few permanently-stuck documents
        occupy every run, and a genuinely recoverable reversal behind them is never
        reached. The money for that one has already left.
        """
        stuck = [self._split_refunded_invoice() for _ in range(2)]
        recoverable = self._refunded_provider_invoice()

        seen: list[int] = []
        with patch(
            "apps.billing.issuers.tasks.queue_invoice_storno",
            side_effect=lambda pk: seen.append(pk) or "task-id",
        ):
            for _ in range(4):
                sweep_owed_reversals(limit=2)

        self.assertIn(
            recoverable.pk,
            seen,
            f"the recoverable reversal was never reached; swept only {sorted(set(seen))} "
            f"while {[i.pk for i in stuck]} are permanently refused",
        )

    def test_a_builtin_invoice_is_never_swept_for_a_provider_reversal(self) -> None:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-000901",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )
        force_status(invoice, "paid")
        force_status(invoice, "refunded")

        queued: list[int] = []
        with patch(
            "apps.billing.issuers.tasks.queue_invoice_storno",
            side_effect=lambda pk: queued.append(pk) or "task-id",
        ):
            sweep_owed_reversals()

        self.assertEqual(queued, [], "built-in invoices are corrected through e-Factura, not the provider")
