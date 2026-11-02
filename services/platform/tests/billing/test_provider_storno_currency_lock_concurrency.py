"""Staff recording a storno must not lock another customer's billing currency."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from decimal import Decimal
from threading import Event
from time import monotonic
from typing import Any
from unittest import skipUnless
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.settings import ro_local_date
from apps.billing.fiscal_correction_models import STATE_COMMUNICATED, STATE_MANUAL_REQUIRED, FiscalCorrection
from apps.billing.fiscal_correction_service import ProviderStornoRecord
from apps.billing.fiscal_correction_worker import process_fiscal_correction
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, ISSUER_SMARTBILL, Invoice, InvoiceSequence
from apps.billing.operator_controls import BillingControlActor, record_manual_provider_storno
from apps.billing.services import InvoiceService
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.users.models import User
from tests.billing import _fiscal_correction_helpers as h


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row and deferred-FK locks are required")
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class ProviderStornoCurrencyLockConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        InvoiceSequence.objects.get_or_create(scope="default")
        self.owner = h.customer("Original customer SRL")
        self.original = h.issued_invoice(self.owner, issuer=ISSUER_SMARTBILL)
        payment = h.paid(self.original)
        refund = h.complete(
            h.pending_refund(invoice=self.original, payment=payment, amount_cents=5000, refund_type="partial")
        )
        self.correction = FiscalCorrection.objects.get(source_refund=refund)
        process_fiscal_correction(str(self.correction.pk))
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_MANUAL_REQUIRED)
        assert self.correction.base_cents is not None
        assert self.correction.tax_cents is not None
        today = ro_local_date(timezone.now())
        self.record = ProviderStornoRecord(
            series="STORNO",
            number=uuid4().hex,
            issued_on=today,
            communicated_on=today,
            currency_code=self.original.currency_id,
            base_cents=self.correction.base_cents,
            tax_cents=self.correction.tax_cents,
            evidence="Provider document and communication verified by staff",
        )
        self.staff = User.objects.create_superuser(email=f"storno-{uuid4().hex}@example.test")
        other = h.customer("Unrelated customer SRL")
        self.order = h.order_for(None, owner=other, billing_address={"country": "RO"})
        product = Product.objects.create(
            name="Unrelated hosting",
            slug=f"unrelated-{uuid4().hex}",
            product_type="shared_hosting",
            is_active=True,
        )
        OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name="Unrelated hosting",
            product_type="shared_hosting",
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.21"),
        )
        self.assertNotEqual(self.order.customer_id, self.original.customer_id)
        self.assertEqual(self.order.currency_id, self.original.currency_id)

    def _record(self) -> str:
        return record_manual_provider_storno(
            correction_id=self.correction.pk,
            record=self.record,
            actor=BillingControlActor(user=self.staff, reason="Record provider evidence", ip_address=None),
        )

    def _invoice(self) -> int:
        result = InvoiceService().create_from_order(Order.objects.get(pk=self.order.pk))
        self.assertTrue(result.is_ok(), result)
        return result.unwrap().pk

    @staticmethod
    def _connected[T](operation: Callable[[], T], pids: list[int]) -> T:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '15s'")
                cursor.execute("SET statement_timeout = '20s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            return operation()
        finally:
            connections.close_all()

    def _held_record(self, entered: Event, release: Event, statements: list[str]) -> str:
        def observe(execute: Callable[..., Any], sql: str, params: Any, many: bool, context: Any) -> Any:
            result = execute(sql, params, many, context)
            if not entered.is_set() and 'FROM "billing_invoices"' in sql and "FOR UPDATE" in sql:
                self.assertIn(self.original.pk, params)
                statements.append(sql)
                entered.set()
                self.assertTrue(release.wait(10), "The invoice observer did not release the staff transaction")
            return result

        with connection.execute_wrapper(observe):
            return self._record()

    def _completion_or_wait[T](self, future: Future[T], pids: list[int], owner: int) -> tuple[bool, str]:
        deadline, poll = monotonic() + 10, Event()
        last = None
        while monotonic() < deadline:
            if future.done():
                future.result()
                return True, ""
            if pids:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_stat_clear_snapshot()")
                    cursor.execute(
                        "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s",
                        [pids[0]],
                    )
                    last = cursor.fetchone()
                if last and last[0] == "Lock" and owner in last[1]:
                    return False, f"pid={pids[0]}, wait_event_type={last[0]}, blockers={last[1]}, query={last[2]}"
            poll.wait(0.01)
        self.fail(f"No completed public operation or exact PostgreSQL lock wait: {last!r}")

    def test_public_writers_succeed_without_competition(self) -> None:
        number = self._record()
        invoice_id = self._invoice()
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_COMMUNICATED)
        note = self.correction.credit_note
        assert note is not None
        self.assertEqual(note.number, number)
        self.assertEqual(Invoice.objects.get(pk=invoice_id).customer_id, self.order.customer_id)

    def test_storno_does_not_block_an_unrelated_customers_invoice_commit(self) -> None:
        entered, release = Event(), Event()
        owner_pids: list[int] = []
        invoice_pids: list[int] = []
        statements: list[str] = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            recording = executor.submit(
                self._connected,
                lambda: self._held_record(entered, release, statements),
                owner_pids,
            )
            try:
                self.assertTrue(entered.wait(10), "Public staff recording did not lock its original invoice")
                # No sequence, other Customer or unrelated Invoice row has been locked by the paused writer.
                self.assertIn('"billing_currencies"', statements[0])
                invoicing = executor.submit(self._connected, self._invoice, invoice_pids)
                completed, query = self._completion_or_wait(invoicing, invoice_pids, owner_pids[0])
                self.assertTrue(
                    completed,
                    f"Unrelated Customer invoice waits on staff-storno backend {owner_pids[0]}: {query}",
                )
                created = Invoice.objects.get(pk=invoicing.result(timeout=5))
                self.assertEqual(created.customer_id, self.order.customer_id)
                self.assertEqual(created.currency_id, self.original.currency_id)
                self.assertGreater(created.total_cents, 0)
            finally:
                release.set()
                recording.result(timeout=15)
        self.assertEqual(
            Invoice.objects.filter(reverses_invoice=self.original, document_kind=DOCUMENT_KIND_CREDIT_NOTE).count(), 1
        )

    def test_competing_staff_recordings_still_serialize_the_same_correction(self) -> None:
        entered, release = Event(), Event()
        owner_pids: list[int] = []
        duplicate_pids: list[int] = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            recording = executor.submit(
                self._connected,
                lambda: self._held_record(entered, release, []),
                owner_pids,
            )
            try:
                self.assertTrue(entered.wait(10))
                duplicate = executor.submit(self._connected, self._record, duplicate_pids)
                completed, query = self._completion_or_wait(duplicate, duplicate_pids, owner_pids[0])
                self.assertFalse(completed, "A duplicate staff recording passed the live correction owner")
                self.assertIn('"billing_fiscal_corrections"', query)
            finally:
                release.set()
                recording.result(timeout=15)
            with self.assertRaises(ValidationError):
                duplicate.result(timeout=15)
        self.assertEqual(
            Invoice.objects.filter(reverses_invoice=self.original, document_kind=DOCUMENT_KIND_CREDIT_NOTE).count(), 1
        )

    def test_a_different_correction_still_waits_for_the_original_invoice(self) -> None:
        payment = self.original.payments.first()
        assert payment is not None
        refund = h.complete(
            h.pending_refund(invoice=self.original, payment=payment, amount_cents=2000, refund_type="partial")
        )
        second = FiscalCorrection.objects.get(source_refund=refund)
        self.assertEqual(second.state, "pending")
        self.assertNotEqual(second.pk, self.correction.pk)
        entered, release = Event(), Event()
        owner_pids: list[int] = []
        allocation_pids: list[int] = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            recording = executor.submit(
                self._connected,
                lambda: self._held_record(entered, release, []),
                owner_pids,
            )
            try:
                self.assertTrue(entered.wait(10))
                allocating = executor.submit(
                    self._connected,
                    lambda: process_fiscal_correction(str(second.pk)),
                    allocation_pids,
                )
                completed, query = self._completion_or_wait(allocating, allocation_pids, owner_pids[0])
                self.assertFalse(completed, "An independent allocation passed the live original invoice owner")
                self.assertIn('"billing_invoices"', query)
            finally:
                release.set()
                recording.result(timeout=15)
            result = allocating.result(timeout=15)
        self.assertEqual(result, {"allocation": "allocated", "issuance": "manual_required"})
        second.refresh_from_db()
        self.assertEqual(second.total_cents, -2000)
        self.assertEqual(second.state, STATE_MANUAL_REQUIRED)
