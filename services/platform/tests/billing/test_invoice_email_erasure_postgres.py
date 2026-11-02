"""A default invoice email must use the buyer snapshot that survived public erasure."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from io import StringIO
from unittest import skipUnless

from django.core.cache import cache
from django.core.management import call_command
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings

from apps.audit.services import GDPRDeletionService
from apps.billing.models import Currency, Invoice, InvoiceSequence, ProformaInvoice, ProformaLine
from apps.billing.services import ProformaConversionService
from apps.customers.models import Customer
from apps.notifications.models import EmailLog
from apps.notifications.services import stored_message
from apps.users.models import CustomerMembership, User


@skipUnless(connection.vendor == "postgresql", "Requires actual PostgreSQL row waits")
@override_settings(DISABLE_AUDIT_SIGNALS=False)
class InvoiceEmailErasureTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        call_command("setup_email_templates", stdout=StringIO())
        InvoiceSequence.objects.get_or_create(scope="default")
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"})
        self.name = "Mara Privatebuyer"
        self.user = User.objects.create_user(
            email="mara.invoice@example.test", password="fixture-pass", first_name="Mara", last_name="Privatebuyer"
        )
        self.customer = Customer.objects.create(
            name=self.name, customer_type="individual", primary_email=self.user.email, status="active"
        )
        CustomerMembership.objects.create(customer=self.customer, user=self.user, role="owner", is_primary=True)
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=currency,
            number="PRO-ERASURE",
            subtotal_cents=10000,
            total_cents=10000,
            bill_to_name=self.name,
            bill_to_email=self.user.email,
            bill_to_country="RO",
        )
        ProformaLine.objects.create(
            proforma=self.proforma,
            description="Recorded service",
            quantity=1,
            unit_price_cents=10000,
            line_total_cents=10000,
        )
        self.request = GDPRDeletionService.create_deletion_request(user=self.user).unwrap()

    def _erase(self) -> None:
        result = GDPRDeletionService.process_deletion_request(self.request)
        self.assertTrue(result.is_ok(), result)

    def _convert(self) -> None:
        result = ProformaConversionService.convert_to_invoice(str(self.proforma.pk))
        self.assertTrue(result.is_ok(), result)

    def _assert_stored_snapshot(self) -> None:
        self.customer.refresh_from_db()
        self.proforma.refresh_from_db()
        self.assertIsNotNone(self.customer.anonymized_at)
        self.assertNotEqual(self.proforma.bill_to_name, self.name)
        invoice = Invoice.objects.get(converted_from_proforma=self.proforma)
        self.assertEqual(invoice.bill_to_name, self.proforma.bill_to_name)
        message = EmailLog.objects.get(template_key="invoice_created", to_addr=invoice.bill_to_email)
        outgoing = stored_message(message)
        self.assertEqual(outgoing.to, [self.proforma.bill_to_email])
        self.assertIsNone(message.customer_id, "Do not change the existing logging association")
        self.assertNotIn(self.name, outgoing.body_html or "")
        self.assertIn(invoice.bill_to_name, outgoing.body_html or "")

    def test_erasure_before_conversion_uses_the_anonymized_snapshot(self) -> None:
        self._erase()
        self._convert()
        self._assert_stored_snapshot()

    def test_conversion_uses_recorded_buyer_name_instead_of_current_display_name(self) -> None:
        self.proforma.bill_to_name = "Recorded billing name"
        self.proforma.save(update_fields=["bill_to_name"])
        self._convert()
        invoice = Invoice.objects.get(converted_from_proforma=self.proforma)
        message = EmailLog.objects.get(template_key="invoice_created", to_addr=invoice.bill_to_email)
        body = stored_message(message).body_html or ""
        self.assertIn(invoice.bill_to_name, body)
        self.assertNotIn(self.customer.get_display_name(), body)

    def test_blank_buyer_snapshot_does_not_invent_a_current_customer_name(self) -> None:
        self.proforma.bill_to_name = ""
        self.proforma.save(update_fields=["bill_to_name"])
        self._convert()
        invoice = Invoice.objects.get(converted_from_proforma=self.proforma)
        self.assertEqual(invoice.bill_to_name, "")
        message = EmailLog.objects.get(template_key="invoice_created", to_addr=invoice.bill_to_email)
        outgoing = stored_message(message)
        self.assertIn(invoice.display_number, outgoing.subject)
        self.assertNotIn(self.customer.get_display_name(), outgoing.body_html or "")

    def _assert_waiting_converter(self, pids: dict[str, int]) -> None:
        deadline = time.monotonic() + 10
        sample = None
        while time.monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid=%s",
                    [pids["converter"]],
                )
                sample = cursor.fetchone()
            if sample and sample[0] == "Lock" and pids["eraser"] in sample[1]:
                break
            time.sleep(0.02)
        self.assertIsNotNone(sample)
        assert sample is not None
        self.assertEqual(sample[0], "Lock")
        self.assertIn(pids["eraser"], sample[1])
        self.assertTrue(sample[2].startswith(f'SELECT "{ProformaInvoice._meta.db_table}".'))
        print(f"Actual public conversion PID {pids['converter']} waits on erasure PID {pids['eraser']}: Lock")

    def test_conversion_waiting_on_public_erasure_does_not_restore_the_old_name(self) -> None:
        held, release, converter_ready = threading.Event(), threading.Event(), threading.Event()
        pids: dict[str, int] = {}
        errors: list[Exception] = []

        def pid() -> int:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                return int(cursor.fetchone()[0])

        def erase() -> None:
            pids["eraser"] = pid()

            def latch(execute: Callable[..., object], sql: str, params: object, many: bool, context: object) -> object:
                result = execute(sql, params, many, context)
                if sql.startswith(f'UPDATE "{ProformaInvoice._meta.db_table}"'):
                    held.set()
                    self.assertTrue(release.wait(20), "Public erasure was not released")
                return result

            with connection.execute_wrapper(latch):
                self._erase()

        def convert() -> None:
            pids["converter"] = pid()
            converter_ready.set()
            self._convert()

        def start(action: Callable[[], None]) -> threading.Thread:
            def run() -> None:
                close_old_connections()
                try:
                    action()
                except Exception as error:
                    errors.append(error)
                finally:
                    connections.close_all()

            thread = threading.Thread(target=run)
            thread.start()
            return thread

        threads = [start(erase)]
        try:
            self.assertTrue(held.wait(10), errors)
            threads.append(start(convert))
            self.assertTrue(converter_ready.wait(5), errors)
            self._assert_waiting_converter(pids)
        finally:
            release.set()
            for thread in threads:
                thread.join(20)
                self.assertFalse(thread.is_alive(), "An owned public writer did not finish")
        if errors:
            raise errors[0]
        self._assert_stored_snapshot()
