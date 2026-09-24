"""A document row created before credit notes existed still claims to be an invoice.

`EFacturaDocument.document_type` is written through `get_or_create(defaults=…)`, which
never touches an existing row. Both live call sites now derive it from the invoice, so
neither produces a stale row — but rows written earlier, when both sites hardcoded
INVOICE, keep that value forever.

It is not cosmetic: `_prepare_and_claim_submission` reads `is_credit_note` from the
STORED field, so such a row is submitted to ANAF as an ordinary invoice carrying negative
amounts, with no reference to the document it reverses.

The repair is bounded by what has already left the building. `{draft, queued, error}` are
exactly the statuses submission is allowed to start from, so nothing has reached ANAF and
the XML is regenerated or re-validated before it does. Anything else either holds an
in-flight claim or describes bytes ANAF has already seen, and rewriting it would make the
row disagree with the document at the other end.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus
from apps.billing.efactura.service import EFacturaService
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    Currency,
    Invoice,
)
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.helpers.migrations import restore_to_leaf

MIGRATE_FROM = ("billing", "0055_providerissuance_submissions")
MIGRATION_UNDER_TEST = ("billing", "0056_repair_credit_note_document_types")


class StaleDocumentTypeRuntimeRepairTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self._seq = 0

    def _invoice(self) -> Invoice:
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FCT-0009{self._seq:02d}",
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return invoice

    def _credit_note(self) -> Invoice:
        self._seq += 1
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"CN-0009{self._seq:02d}",
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=self._invoice(),
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_BUILTIN,
        )

    def _stale_document(self, invoice: Invoice, status: str) -> EFacturaDocument:
        """The row an older implementation left: a credit note typed as an invoice."""
        document = EFacturaDocument.objects.create(
            invoice=invoice,
            document_type=EFacturaDocumentType.INVOICE.value,
            environment="test",
        )
        fields: dict[str, object] = {"status": status}
        if status == EFacturaStatus.UPLOADING.value:
            # `efactura_claim_state_consistent` requires an uploading row to carry its
            # claim, which is exactly why this status is not repairable.
            fields |= {
                "submission_claim_token": uuid.uuid4(),
                "submission_claimed_at": timezone.now(),
                "submission_claim_expires_at": timezone.now() + timezone.timedelta(minutes=10),
            }
        EFacturaDocument.objects.filter(pk=document.pk).update(**fields)
        return EFacturaDocument.objects.get(pk=document.pk)

    def test_a_stale_row_is_repaired_before_it_can_be_submitted(self) -> None:
        for status in (EFacturaStatus.DRAFT.value, EFacturaStatus.QUEUED.value, EFacturaStatus.ERROR.value):
            with self.subTest(status=status):
                credit_note = self._credit_note()
                self._stale_document(credit_note, status)

                repaired = EFacturaService()._get_or_create_document(credit_note)

                self.assertEqual(repaired.document_type, EFacturaDocumentType.CREDIT_NOTE.value)
                self.assertEqual(
                    EFacturaDocument.objects.get(pk=repaired.pk).document_type,
                    EFacturaDocumentType.CREDIT_NOTE.value,
                    "the correction has to be persisted, not only returned",
                )

    def test_a_row_anaf_has_already_seen_is_left_alone(self) -> None:
        """Rewriting it would make our record disagree with the document at ANAF."""
        for status in (
            EFacturaStatus.SUBMITTED.value,
            EFacturaStatus.ACCEPTED.value,
            EFacturaStatus.REJECTED.value,
            EFacturaStatus.UPLOADING.value,
        ):
            with self.subTest(status=status):
                credit_note = self._credit_note()
                stale = self._stale_document(credit_note, status)

                returned = EFacturaService()._get_or_create_document(credit_note)

                self.assertEqual(returned.document_type, EFacturaDocumentType.INVOICE.value)
                self.assertEqual(
                    EFacturaDocument.objects.get(pk=stale.pk).document_type,
                    EFacturaDocumentType.INVOICE.value,
                )

    def test_a_document_deliberately_typed_as_a_credit_note_is_left_alone(self) -> None:
        """The repair runs in one direction only, and this is why.

        Typing an ordinary invoice's document CREDIT_NOTE is how the credit-note
        submission route is exercised, so a repair that forced agreement in both
        directions would silently reroute it - which is exactly what it did before this
        was narrowed.
        """
        invoice = self._invoice()
        document = EFacturaDocument.objects.create(
            invoice=invoice,
            document_type=EFacturaDocumentType.CREDIT_NOTE.value,
            environment="test",
        )

        EFacturaService()._get_or_create_document(invoice)

        self.assertEqual(
            EFacturaDocument.objects.get(pk=document.pk).document_type,
            EFacturaDocumentType.CREDIT_NOTE.value,
        )

    def test_an_ordinary_invoice_is_not_disturbed(self) -> None:
        """The regression guard: the repair is keyed on a real disagreement."""
        invoice = self._invoice()
        self._stale_document(invoice, EFacturaStatus.DRAFT.value)

        returned = EFacturaService()._get_or_create_document(invoice)

        self.assertEqual(returned.document_type, EFacturaDocumentType.INVOICE.value)


class StaleDocumentTypeMigrationTest(TransactionTestCase):
    """A deployment that already holds such rows cannot wait for the runtime path."""

    def tearDown(self) -> None:
        restore_to_leaf("billing")
        super().tearDown()

    def _seed_at(self, state: str) -> object:
        executor = MigrationExecutor(connection)
        executor.migrate([MIGRATE_FROM])
        old = executor.loader.project_state([MIGRATE_FROM]).apps

        customer_model = old.get_model("customers", "Customer")
        currency_model = old.get_model("billing", "Currency")
        invoice_model = old.get_model("billing", "Invoice")
        document_model = old.get_model("billing", "EFacturaDocument")

        customer = customer_model.objects.create(
            name="Test Co", customer_type="company", company_name="Test Co", status="active"
        )
        currency, _ = currency_model.objects.get_or_create(
            code="RON", defaults={"symbol": "L", "decimals": 2, "name": "Romanian Leu"}
        )
        original = invoice_model.objects.create(
            customer=customer,
            currency=currency,
            number="FCT-000950",
            status="issued",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Co",
            bill_to_country="RO",
        )
        credit_note = invoice_model.objects.create(
            customer=customer,
            currency=currency,
            number="CN-000950",
            status="issued",
            document_kind="credit_note",
            reverses_invoice=original,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Co",
            bill_to_country="RO",
        )
        document = document_model.objects.create(
            invoice=credit_note, document_type="invoice", status=state, environment="test"
        )
        return document.pk

    def _document_type_after_migration(self, pk: object) -> str:
        MigrationExecutor(connection).migrate([MIGRATION_UNDER_TEST])
        new = MigrationExecutor(connection).loader.project_state([MIGRATION_UNDER_TEST]).apps
        return str(new.get_model("billing", "EFacturaDocument").objects.get(pk=pk).document_type)

    def test_an_unsubmitted_row_is_repaired(self) -> None:
        pk = self._seed_at("draft")

        self.assertEqual(self._document_type_after_migration(pk), "credit_note")

    def test_a_submitted_row_is_left_as_filed(self) -> None:
        pk = self._seed_at("accepted")

        self.assertEqual(self._document_type_after_migration(pk), "invoice")
