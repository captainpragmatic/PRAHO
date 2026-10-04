"""Every path that creates an invoice must honour the configured issuer.

The issuer decision was made in exactly one of the creation services. The others
kept allocating a PRAHO number inline, so selecting SmartBill silently left those
documents numbered by PRAHO's own fiscal sequence — a legal act under an authority
the operator did not choose, frozen permanently on the document.

And a reversal that cannot be enqueued must still be recoverable: the refund has
already moved money, so losing the correction leaves the customer holding a full
invoice with nothing reversing it. It is recovered through the refund's fiscal
correction, which the recording and issuance sweeps both find again.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing import fiscal_correction_worker
from apps.billing.fiscal_correction_models import STATE_ISSUED, STATE_MANUAL_REQUIRED, FiscalCorrection
from apps.billing.fiscal_correction_service import record_obligation, sweep_fiscal_corrections
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
    InvoiceSequence,
)
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.policy import can_switch_invoice_issuer
from apps.billing.issuers.service import issue_invoice_externally
from apps.billing.issuers.tasks import sweep_pending_issuances
from apps.billing.pdf_generators import RomanianInvoicePDFGenerator
from apps.billing.refund_models import Refund
from apps.billing.services import InvoiceService
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.settings.services import SettingsService
from config.settings.test import LOCMEM_TEST_CACHE
from tests.billing import _fiscal_correction_helpers as h
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

    def _swept(self, **sweep: int) -> list[str]:
        """The corrections one issuance sweep hands to the worker."""
        seen: list[str] = []
        with patch.object(
            fiscal_correction_worker, "process_fiscal_correction", side_effect=lambda pk: seen.append(pk) or {}
        ):
            fiscal_correction_worker.sweep_fiscal_correction_issuance(**sweep)
        return seen

    def test_a_reversal_whose_enqueue_was_lost_is_found_again(self) -> None:
        """The refund settled and no worker ever ran: no hook fired for a row born completed, which
        is what a lost enqueue leaves behind. The recording sweep finds the refund, and the issuance
        sweep then hands its correction to the worker."""
        invoice = self._refunded_provider_invoice()
        self.assertFalse(FiscalCorrection.objects.exists(), "precondition: nothing recorded, nothing queued")

        sweep_fiscal_corrections()
        swept = self._swept()

        correction = FiscalCorrection.objects.get(original=invoice)
        self.assertEqual(swept, [str(correction.pk)], "the owed reversal must be picked up again")

    def test_a_reversal_awaiting_a_person_is_not_swept_again(self) -> None:
        """An unknown outcome is the reconciliation queue's: retrying it would only be refused."""
        invoice = self._refunded_provider_invoice()
        correction = h.whole_correction(Refund.objects.get(invoice=invoice))
        credit_note = Invoice.objects.create(
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
        ProviderIssuance.objects.create(
            invoice=credit_note,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.OUTCOME_UNKNOWN.value,
            fiscal_correction=correction,
        )

        self.assertEqual(self._swept(), [], "a reversal that may exist at the provider waits for an operator")

    @override_settings(CACHES=LOCMEM_TEST_CACHE)
    def test_corrections_waiting_for_staff_do_not_starve_the_queue(self) -> None:
        """A correction the provider cannot issue waits for staff, however long that takes. It is
        not a candidate at all, so it can never occupy a run while a recoverable one waits."""
        for _ in range(2):
            stuck = h.whole_correction(Refund.objects.get(invoice=self._refunded_provider_invoice()))
            stuck.require_manual_issuance()
            stuck.save()
        recoverable = record_obligation(Refund.objects.get(invoice=self._refunded_provider_invoice()))
        assert recoverable is not None

        self.assertEqual(self._swept(limit=1), [str(recoverable.pk)])
        self.assertEqual(FiscalCorrection.objects.filter(state=STATE_MANUAL_REQUIRED).count(), 2)

    def test_a_builtin_invoices_correction_never_reaches_a_provider_reversal(self) -> None:
        invoice = h.issued_invoice(self.customer, number="INV-000901")
        payment = h.paid(invoice)
        refund = h.complete(h.pending_refund(invoice=invoice, payment=payment))
        correction = FiscalCorrection.objects.get(source_refund=refund)

        with (
            patch("apps.billing.issuers.service.issue_storno_for_correction", side_effect=AssertionError),
            patch.object(fiscal_correction_worker, "deliver_credit_note"),
        ):
            fiscal_correction_worker.process_fiscal_correction(str(correction.pk))

        correction.refresh_from_db()
        self.assertEqual(correction.state, STATE_ISSUED, correction.last_error)
        self.assertEqual(correction.credit_note.issuer_provider, ISSUER_BUILTIN)
        self.assertFalse(ProviderIssuance.objects.exists())


class CreditNotesAreNeverIssuedAsInvoicesTests(TransactionTestCase):
    """A reversal must reach the reversal endpoint, or it creates a second document.

    `pending` records that a provider call is owed, not which one. Pacing hands a
    rate-gated storno's claim back to `pending` by design, so the issuance sweep sees
    an unnumbered document with a pending claim and cannot tell it from an invoice
    awaiting its first number. Dispatching it to the issuance task posts it to
    `/invoice`, which mints a brand-new fiscal document with negative amounts while
    the invoice it was meant to reverse stays outstanding - and a SmartBill invoice
    that is not last in its series cannot be deleted afterwards.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _credit_note(self) -> Invoice:
        original = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="FCT-000700",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        credit_note = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            issuer_provider=ISSUER_SMARTBILL,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )
        ProviderIssuance.objects.create(
            invoice=credit_note, provider=ISSUER_SMARTBILL, state=IssuanceState.PENDING.value
        )
        return credit_note

    def test_the_issuance_entry_point_refuses_a_credit_note(self) -> None:
        credit_note = self._credit_note()

        submitted: list[object] = []
        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit",
            side_effect=lambda *a, **k: submitted.append(a),
        ):
            result = issue_invoice_externally(credit_note.pk)

        self.assertTrue(result.is_err())
        self.assertIn("reversal endpoint", result.error)
        self.assertEqual(submitted, [], "a credit note must never reach the issuance endpoint")
        credit_note.refresh_from_db()
        self.assertIsNone(credit_note.number)

    def test_the_issuance_sweep_does_not_pick_up_a_credit_note(self) -> None:
        credit_note = self._credit_note()

        queued: list[int] = []
        with patch(
            "apps.billing.issuers.tasks.queue_invoice_issuance",
            side_effect=lambda pk: queued.append(pk) or "task-id",
        ):
            sweep_pending_issuances()

        self.assertNotIn(credit_note.pk, queued, "a reversal is resumed through its correction, never as an invoice")


class LeavingTheIntegrationIsNeverBlockedTests(TestCase):
    """Switching back to built-in is the remedy when the provider misbehaves.

    Blocking it on unresolved provider work means one ambiguous outcome latches the
    setting permanently, in every write path at once - the chokepoint being universal
    is exactly what makes it unrecoverable - since `outcome_unknown` has a single exit
    that needs a human.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _stuck_issuance(self) -> None:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(
            invoice=invoice, provider=ISSUER_SMARTBILL, state=IssuanceState.OUTCOME_UNKNOWN.value
        )

    def test_an_unknown_outcome_does_not_trap_the_operator(self) -> None:
        self._stuck_issuance()

        outcome = can_switch_invoice_issuer(ISSUER_BUILTIN)

        self.assertTrue(
            outcome.is_ok(),
            f"returning to the built-in issuer must stay available; blocked by "
            f"{[b.reason for b in getattr(outcome, 'error', ())]}",
        )

    def test_an_unknown_outcome_still_blocks_switching_further_in(self) -> None:
        """The other direction must keep its guard."""
        self._stuck_issuance()

        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.validate_configuration",
            return_value=Ok(None),
        ):
            outcome = can_switch_invoice_issuer(ISSUER_SMARTBILL)

        self.assertTrue(outcome.is_err())
        self.assertTrue(any("unresolved" in b.reason for b in outcome.error))

    def test_the_settings_write_path_lets_the_operator_leave(self) -> None:
        self._stuck_issuance()

        result = SettingsService.update_setting("billing.invoice_issuer", ISSUER_BUILTIN, reason="test")

        self.assertTrue(result.is_ok(), msg=getattr(result, "error", ""))


class NothingRendersTheWordNoneTests(TestCase):
    """`number` became nullable; several consumers still read it raw.

    A document awaiting issuance renders as the literal string "None" wherever a
    surface interpolates the field instead of going through `display_number`. On an
    audit row that is worse: `AuditEvent.description` is immutable, so "Invoice None
    created" is permanent and untraceable.
    """

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _unnumbered(self) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )

    def test_the_audit_row_is_traceable_without_a_number(self) -> None:
        invoice = self._unnumbered()

        descriptions = [event.description for event in AuditEvent.objects.filter(description__icontains="invoice")]
        self.assertTrue(descriptions, "invoice creation must be audited")
        for description in descriptions:
            self.assertNotIn("Invoice None", description)
        self.assertTrue(
            any(f"invoice:{invoice.pk}" in d for d in descriptions),
            f"the audit row must identify the document; got {descriptions}",
        )

    def test_a_numbered_invoice_still_audits_under_its_legal_number(self) -> None:
        """The regression guard: `audit_reference` must not mask a real number."""
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-AUD-0001",
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )

        self.assertTrue(
            AuditEvent.objects.filter(description__icontains="INV-AUD-0001").exists(),
            "a numbered invoice must still be audited under its legal number",
        )

    def test_display_number_stands_in_for_humans(self) -> None:
        invoice = self._unnumbered()

        self.assertNotEqual(invoice.display_number, "None")
        self.assertNotIn("None", invoice.display_number)
        self.assertEqual(invoice.audit_reference, f"invoice:{invoice.pk}")

    def test_the_pdf_filename_never_says_none(self) -> None:
        invoice = self._unnumbered()

        filename = RomanianInvoicePDFGenerator(invoice)._get_filename()

        self.assertNotIn("None", filename)
