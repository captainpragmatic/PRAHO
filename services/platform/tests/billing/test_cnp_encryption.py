"""The CNP on an invoice or proforma is encrypted at rest, bound to its row (ADR-0040).

`bill_to_cnp` is an EncryptedTextField: the Python value is a string, "" when there is none,
and the column holds NULL or AAD-bound ciphertext. The AAD carries the row's
`encryption_context_id`, which a trigger keeps immutable (billing 0010). These tests run on
SQLite in the normal suite and on PostgreSQL in the integration job.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from django.core.exceptions import ValidationError
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.db.models import Model
from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import Invoice
from apps.billing.issuers.service import _get_or_create_credit_note
from apps.billing.proforma_models import ProformaInvoice
from apps.common.encryption import DecryptionError, EncryptionError
from tests.billing import _fiscal_correction_helpers as h

CNP = "1850101123451"
OTHER_CNP = "2850101123456"


def stored(model: type[Model], field: str, pk: Any) -> str | None:
    """The column's raw value, as the database holds it."""
    column = connection.ops.quote_name(model._meta.get_field(field).column)
    table = connection.ops.quote_name(model._meta.db_table)
    expression = f"{column}::text" if connection.vendor == "postgresql" else column
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT {expression} FROM {table} WHERE id = %s", [pk])  # noqa: S608
        value = cursor.fetchone()[0]
    return None if value is None else str(value)


class CNPDocumentMixin:
    def setUp(self) -> None:
        self.customer = h.customer("CNP Document SRL")
        self.currency = h.ron()

    def invoice(self, **fields: Any) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"INV-{uuid.uuid4().hex[:8]}",
            bill_to_country="RO",
            **fields,
        )

    def proforma(self, **fields: Any) -> ProformaInvoice:
        return ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PRO-{uuid.uuid4().hex[:8]}",
            valid_until=timezone.now() + timedelta(days=30),
            bill_to_country="RO",
            **fields,
        )

    def documents(self, **fields: Any) -> list[Invoice | ProformaInvoice]:
        return [self.invoice(**fields), self.proforma(**fields)]


class CNPAtRestTests(CNPDocumentMixin, TestCase):
    def test_the_cnp_is_stored_as_ciphertext(self) -> None:
        for document in self.documents(bill_to_cnp=CNP):
            with self.subTest(model=type(document).__name__):
                raw = stored(type(document), "bill_to_cnp", document.pk)
                assert raw is not None
                self.assertIn("aes:v2:", raw)
                self.assertNotIn(CNP, raw)
                document.refresh_from_db()
                self.assertEqual(document.bill_to_cnp, CNP)

    def test_no_cnp_is_stored_as_null_and_reads_back_empty(self) -> None:
        for value in ("", None):
            for document in self.documents(bill_to_cnp=value):
                with self.subTest(model=type(document).__name__, value=value):
                    self.assertIsNone(stored(type(document), "bill_to_cnp", document.pk))
                    self.assertEqual(document.bill_to_cnp, "")
                    self.assertEqual(type(document).objects.get(pk=document.pk).bill_to_cnp, "")

    def test_a_ciphertext_moved_to_another_row_cannot_be_read(self) -> None:
        source = self.invoice(bill_to_cnp=CNP)
        target = self.invoice(bill_to_cnp=OTHER_CNP)
        table = connection.ops.quote_name(Invoice._meta.db_table)
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE {table} SET bill_to_cnp = (SELECT bill_to_cnp FROM {table} WHERE id = %s) "  # noqa: S608
                "WHERE id = %s",
                [source.pk, target.pk],
            )

        with self.assertRaises(DecryptionError):
            Invoice.objects.get(pk=target.pk)

    def test_the_encryption_context_cannot_change(self) -> None:
        for document in self.documents(bill_to_cnp=CNP):
            model = type(document)
            with self.subTest(model=model.__name__):
                with self.assertRaises(DatabaseError), transaction.atomic():
                    model.objects.filter(pk=document.pk).update(encryption_context_id=uuid.uuid4())

                self.assertEqual(model.objects.get(pk=document.pk).bill_to_cnp, CNP)

    def test_a_cnp_cannot_be_written_without_its_row(self) -> None:
        for document in self.documents():
            model = type(document)
            with self.subTest(model=model.__name__):
                with self.assertRaises(EncryptionError), transaction.atomic():
                    model.objects.filter(pk=document.pk).update(bill_to_cnp=CNP)
                document.bill_to_cnp = CNP
                with self.assertRaises(EncryptionError), transaction.atomic():
                    model.objects.bulk_update([document], ["bill_to_cnp"])

    def test_a_string_that_looks_like_ciphertext_is_refused(self) -> None:
        donor = self.invoice(bill_to_cnp=CNP)
        ciphertext = stored(Invoice, "bill_to_cnp", donor.pk)
        assert ciphertext is not None
        document = self.invoice()
        document.bill_to_cnp = ciphertext.strip('"')

        with self.assertRaises(EncryptionError):
            document.save()

    def test_a_deferred_cnp_is_loaded_on_access(self) -> None:
        invoice = self.invoice(bill_to_cnp=CNP)

        self.assertEqual(Invoice.objects.defer("bill_to_cnp").get(pk=invoice.pk).bill_to_cnp, CNP)
        self.assertEqual(Invoice.objects.only("pk").get(pk=invoice.pk).bill_to_cnp, CNP)
        invoice.bill_to_cnp = ""
        invoice.refresh_from_db(fields=["bill_to_cnp"])
        self.assertEqual(invoice.bill_to_cnp, CNP)

    def test_isnull_tells_documents_with_a_cnp_from_the_rest(self) -> None:
        with_cnp = self.invoice(bill_to_cnp=CNP)
        without = self.invoice()

        self.assertEqual(set(Invoice.objects.filter(bill_to_cnp__isnull=False)), {with_cnp})
        self.assertEqual(set(Invoice.objects.filter(bill_to_cnp__isnull=True)), {without})


class OneFiscalIdentifierTests(CNPDocumentMixin, TestCase):
    """A document has a business tax ID or a CNP, never both; an empty CNP is stored as NULL."""

    def test_python_side_validation_matches_the_database(self) -> None:
        cases = (
            ({"bill_to_tax_id": "14399840", "bill_to_cnp": ""}, True),
            ({"bill_to_tax_id": "", "bill_to_cnp": CNP}, True),
            ({"bill_to_tax_id": "", "bill_to_cnp": ""}, True),
            ({"bill_to_tax_id": "14399840", "bill_to_cnp": CNP}, False),
        )
        for factory in (self.invoice, self.proforma):
            for fields, allowed in cases:
                model = Invoice if factory == self.invoice else ProformaInvoice
                with self.subTest(model=model.__name__, **fields):
                    unsaved = model(customer=self.customer, currency=self.currency, **fields)
                    if allowed:
                        unsaved.validate_constraints()
                        factory(**fields)
                    else:
                        with self.assertRaises(ValidationError):
                            unsaved.validate_constraints()
                        with self.assertRaises(IntegrityError), transaction.atomic():
                            factory(**fields)


class LockedInvoiceCNPTests(CNPDocumentMixin, TestCase):
    def issued(self, cnp: str) -> Invoice:
        invoice = self.invoice(bill_to_cnp=cnp, due_at=timezone.now() + timedelta(days=30))
        invoice.issue()
        invoice.save()
        self.assertIsNotNone(invoice.locked_at)
        return invoice

    def test_an_issued_invoice_saves_again_with_its_cnp(self) -> None:
        invoice = self.issued(CNP)
        invoice.meta = {"note": "saved again"}
        invoice.save()

        self.assertEqual(Invoice.objects.get(pk=invoice.pk).bill_to_cnp, CNP)

    def test_an_issued_invoice_keeps_its_cnp(self) -> None:
        for replacement in (OTHER_CNP, "", None):
            invoice = self.issued(CNP)
            with self.subTest(replacement=replacement):
                invoice.bill_to_cnp = replacement
                with self.assertRaises(ValidationError):
                    invoice.save()
                with self.assertRaises(ValidationError):
                    Invoice.objects.filter(pk=invoice.pk).update(bill_to_cnp=None)
                self.assertEqual(Invoice.objects.get(pk=invoice.pk).bill_to_cnp, CNP)

    def test_none_on_an_issued_invoice_without_a_cnp_is_no_change(self) -> None:
        invoice = self.issued("")
        invoice.bill_to_cnp = None
        invoice.save()

        self.assertEqual(invoice.bill_to_cnp, "")
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).bill_to_cnp, "")

    def test_clearing_without_a_row_works_on_a_proforma(self) -> None:
        proforma = self.proforma(bill_to_cnp=CNP)

        ProformaInvoice.objects.filter(pk=proforma.pk).update(bill_to_cnp=None)

        self.assertEqual(ProformaInvoice.objects.get(pk=proforma.pk).bill_to_cnp, "")


class CNPReadersTests(CNPDocumentMixin, TestCase):
    def test_a_credit_note_carries_the_original_s_whole_snapshot(self) -> None:
        snapshot = {
            "bill_to_name": "Ion Popescu",
            "bill_to_tax_id": "",
            "bill_to_cnp": CNP,
            "bill_to_registration_number": "J40/1234/2020",
            "bill_to_email": "ion@example.test",
            "bill_to_address1": "Str. Victoriei 10",
            "bill_to_address2": "Ap. 3",
            "bill_to_city": "București",
            "bill_to_region": "București",
            "bill_to_postal": "010101",
        }
        self.assertEqual(set(snapshot) | {"bill_to_country"}, set(Invoice._BILLING_SNAPSHOT_FIELDS))
        original = h.issued_invoice(self.customer, issue=False)
        for field, value in snapshot.items():
            setattr(original, field, value)
        original.save()
        original = Invoice.objects.get(pk=original.pk)

        credit_note = Invoice.objects.get(pk=_get_or_create_credit_note(original, h.correction_of(original)).pk)

        for field in sorted(Invoice._BILLING_SNAPSHOT_FIELDS):
            with self.subTest(field=field):
                self.assertEqual(getattr(credit_note, field), getattr(original, field))
        self.assertEqual(credit_note.bill_to_cnp, CNP)
