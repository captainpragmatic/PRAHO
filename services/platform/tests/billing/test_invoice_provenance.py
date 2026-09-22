"""Phase 1: per-document issuer provenance and provisional numbering.

These tests exist because an invoice issued by an external provider does not have
its legal number until the provider responds. The document must therefore be able
to exist, durably and in quantity, before a number is assigned.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    DOCUMENT_KIND_INVOICE,
    ISSUER_BUILTIN,
    ISSUER_SMARTBILL,
)
from apps.billing.models import Currency, Invoice
from tests.factories.billing_factories import CustomerFactory
from tests.helpers.fsm_helpers import force_status


def _currency(code: str = "RON") -> Currency:
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": "L", "decimals": 2})
    return obj


class ProvisionalNumberingTests(TestCase):
    """An unissued invoice has no number, and many may exist at once."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def _unnumbered_invoice(self) -> Invoice:
        """Create an invoice the way a deferred-issuance path would: no number."""
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
        )

    def test_two_unissued_invoices_can_coexist(self) -> None:
        """THE discriminator for the static-unique-default defect.

        `number` was `CharField(unique=True, default="TMP-000")`. A static default on
        a unique column means exactly one row may hold it, so the second deferred
        issuance raised IntegrityError. Reverting the field change fails this test.
        """
        first = self._unnumbered_invoice()
        second = self._unnumbered_invoice()

        self.assertIsNone(first.number)
        self.assertIsNone(second.number)
        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(Invoice.objects.filter(number__isnull=True).count(), 2)

    def test_assigned_numbers_remain_unique(self) -> None:
        """Nullability must not weaken uniqueness for real numbers."""
        first = self._unnumbered_invoice()
        first.number = "INV-000001"
        first.save(update_fields=["number"])

        second = self._unnumbered_invoice()
        second.number = "INV-000001"
        with self.assertRaises(IntegrityError), transaction.atomic():
            second.save(update_fields=["number"])


class IssuerProvenanceTests(TestCase):
    """Provenance is stamped per document and frozen with the fiscal snapshot."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def _invoice(self, **kwargs: object) -> Invoice:
        defaults: dict[str, object] = {
            "customer": self.customer,
            "currency": self.currency,
            "status": "draft",
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": 12100,
            "bill_to_name": "Test Company SRL",
        }
        defaults.update(kwargs)
        return Invoice.objects.create(**defaults)

    def test_defaults_to_builtin_issuer(self) -> None:
        self.assertEqual(self._invoice().issuer_provider, ISSUER_BUILTIN)

    def test_document_defaults_to_invoice_kind(self) -> None:
        self.assertEqual(self._invoice().document_kind, DOCUMENT_KIND_INVOICE)

    def test_issuer_provider_is_frozen_once_locked(self) -> None:
        """Provenance is in the fiscal snapshot, so a locked document cannot change issuer.

        Without this, flipping the Settings toggle could retroactively rewrite who
        issued a document that has already gone to a customer and to ANAF.
        """
        invoice = self._invoice(number="INV-LOCK-001", status="issued", locked_at=timezone.now())

        invoice.issuer_provider = ISSUER_SMARTBILL
        with self.assertRaises(ValidationError):
            invoice.save()

    def test_locked_document_must_have_a_number(self) -> None:
        """DB-level guarantee: nothing is locked without its legal number."""
        invoice = self._invoice()
        invoice.locked_at = timezone.now()
        with self.assertRaises(IntegrityError), transaction.atomic():
            # Bypass model save() to prove the constraint lives in the database.
            Invoice.objects.filter(pk=invoice.pk).update(locked_at=timezone.now())

    def test_credit_note_must_reference_the_invoice_it_reverses(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._invoice(
                document_kind=DOCUMENT_KIND_CREDIT_NOTE,
                subtotal_cents=-10000,
                tax_cents=-2100,
                total_cents=-12100,
            )

    def test_credit_note_totals_must_be_non_positive(self) -> None:
        original = self._invoice(number="INV-ORIG-001")
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._invoice(
                document_kind=DOCUMENT_KIND_CREDIT_NOTE,
                reverses_invoice=original,
                subtotal_cents=10000,
                tax_cents=2100,
                total_cents=12100,
            )

    def test_invoice_totals_must_not_be_negative(self) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            self._invoice(subtotal_cents=-10000, tax_cents=-2100, total_cents=-12100)

    def test_external_issuer_never_gets_a_local_sequence_number(self) -> None:
        """The guard that keeps two numbering authorities from both minting.

        A SmartBill invoice reaching `issued` without a provider number is a bug in
        the issuance protocol. Allocating a local number here would produce a
        document whose number differs from the one the customer and ANAF received.
        """
        invoice = self._invoice(issuer_provider=ISSUER_SMARTBILL)

        # The guard is in pre_save, so ANY save into `issued` trips it, which is
        # the point: there is no save path that quietly mints a local number.
        with self.assertRaises(ValueError) as ctx:
            force_status(invoice, "issued")
        self.assertIn("refusing to allocate a local number", str(ctx.exception))

        invoice.refresh_from_db()
        self.assertIsNone(invoice.number)

    def test_display_number_is_a_real_string_not_a_lazy_proxy(self) -> None:
        """Lazy proxies serialise badly into audit JSON; this must be a concrete str."""
        self.assertIs(type(self._invoice().display_number), str)


class BlankNumberTests(TestCase):
    """A blank number is not a third state. It collapses to "no number"."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def _invoice(self, **kwargs: object) -> Invoice:
        defaults: dict[str, object] = {
            "customer": self.customer,
            "currency": self.currency,
            "status": "draft",
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": 12100,
            "bill_to_name": "Test Company SRL",
        }
        defaults.update(kwargs)
        return Invoice.objects.create(**defaults)

    def test_empty_string_number_is_stored_as_null(self) -> None:
        """Otherwise "" satisfies every presence check while meaning nothing."""
        invoice = self._invoice(number="")
        invoice.refresh_from_db()
        self.assertIsNone(invoice.number)

    def test_whitespace_number_is_stored_as_null(self) -> None:
        invoice = self._invoice(number="   ")
        invoice.refresh_from_db()
        self.assertIsNone(invoice.number)

    def test_many_blank_numbered_invoices_can_coexist(self) -> None:
        """The blank variant must not reintroduce the uniqueness collision."""
        for _ in range(3):
            self._invoice(number="")
        self.assertEqual(Invoice.objects.filter(number__isnull=True).count(), 3)

    def test_blank_number_cannot_be_locked_even_bypassing_save(self) -> None:
        """`.update()` skips save(), so the database has to refuse this itself."""
        invoice = self._invoice(number="INV-BLANK-001")
        with self.assertRaises(IntegrityError), transaction.atomic():
            Invoice.objects.filter(pk=invoice.pk).update(number="", locked_at=timezone.now())

    def test_external_issuer_with_blank_number_is_still_refused(self) -> None:
        """The allocation guard must key off "unnumbered", not off None specifically."""
        invoice = self._invoice(issuer_provider=ISSUER_SMARTBILL, number="")
        with self.assertRaises(ValueError):
            force_status(invoice, "issued")

    def test_credit_note_cannot_reverse_itself(self) -> None:
        original = self._invoice(number="INV-SELF-001")
        credit = self._invoice(
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            Invoice.objects.filter(pk=credit.pk).update(reverses_invoice=credit.pk)
