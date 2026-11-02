"""Normal invoice creation must populate the actual customer-facing email."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from io import StringIO
from uuid import uuid4

from django.core.cache import cache
from django.core.management import call_command
from django.db import transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from django_q.conf import Conf
from django_q.models import OrmQ

from apps.billing.invoice_models import ISSUER_BUILTIN, ISSUER_SMARTBILL, Invoice, InvoiceSequence
from apps.billing.issuers.policy import issuer_for_new_document
from apps.billing.models import Payment
from apps.billing.services import InvoiceService
from apps.notifications.models import EmailLog, EmailTemplate
from apps.notifications.services import EmailService, stored_message
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from tests.factories.billing_factories import CurrencyFactory, CustomerFactory


@override_settings(DISABLE_AUDIT_SIGNALS=False, EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class InvoiceSignalEmailContentTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        call_command("setup_email_templates", stdout=StringIO())
        InvoiceSequence.objects.get_or_create(scope="default")
        self.customer = CustomerFactory(
            company_name="Email Content Buyer SRL", primary_email="email-content@example.test"
        )
        self.currency = CurrencyFactory()
        self.order = Order.objects.create(
            order_number=f"EMAIL-{uuid4().hex}",
            customer=self.customer,
            currency=self.currency,
            customer_name=self.customer.get_display_name(),
            customer_email=self.customer.primary_email,
            billing_address={"country": "RO"},
        )
        product = Product.objects.create(
            name="Email content hosting", slug=f"email-{uuid4().hex}", product_type="shared_hosting", is_active=True
        )
        OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name=product.name,
            product_type="shared_hosting",
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.21"),
        )

    def _create_invoice(self) -> Invoice:
        self.assertFalse(Conf.SYNC, "Proof requires real asynchronous ORM publication")
        self.assertEqual(issuer_for_new_document(), (ISSUER_BUILTIN, False))
        result = InvoiceService().create_from_order(self.order)
        self.assertTrue(result.is_ok(), result)
        invoice = result.unwrap()
        self.assertIsInstance(invoice, Invoice)
        assert isinstance(invoice, Invoice)
        self.assertTrue(invoice.number, "The builtin producer must supply its real number before notification")
        self.assertGreater(invoice.total_cents, 0)
        self.assertEqual(invoice.status, "draft")
        self.assertIsNone(invoice.due_at, "The created message must not invent a later due date")
        return invoice

    def _assert_queued(self, message: EmailLog) -> None:
        self.assertEqual(message.status, "queued")
        publications = [
            row.task
            for row in OrmQ.objects.all()
            if row.task.get("func") == "apps.notifications.tasks.send_email_task"
            and row.task.get("kwargs", {}).get("email_log_id") == str(message.pk)
        ]
        self.assertEqual(len(publications), 1, "The real committed message must have its normal ORM task")

    def _assert_content(self, message: EmailLog, invoice: Invoice) -> None:
        assert invoice.number is not None
        outgoing = stored_message(message)
        self.assertIsNotNone(outgoing.body_html)
        assert outgoing.body_html is not None
        self.assertIn(invoice.number, outgoing.subject)
        self.assertIn(invoice.number, outgoing.body_html)
        self.assertIn(self.customer.get_display_name(), outgoing.body_html)
        self.assertIn(str(invoice.total), outgoing.body_html)
        self.assertIn(invoice.currency_id, outgoing.body_html)

    def _assert_identity(self, key: str, invoice: Invoice) -> EmailLog:
        message = EmailLog.objects.get(template_key=key, to_addr=invoice.bill_to_email)
        self._assert_queued(message)
        outgoing = stored_message(message)
        self.assertIn(invoice.display_number, outgoing.subject)
        self.assertIn(invoice.display_number, outgoing.body_html or "")
        self.assertIn(self.customer.get_display_name(), outgoing.body_html or "")
        self.assertIsNone(message.customer_id, "Content fix must preserve existing association semantics")
        return message

    def _issue(self, invoice: Invoice) -> None:
        invoice.issue()
        invoice.save()
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "issued")

    def test_public_creation_renders_the_seeded_created_email(self) -> None:
        invoice = self._create_invoice()
        message = EmailLog.objects.get(template_key="invoice_created", to_addr=invoice.bill_to_email)
        self._assert_queued(message)
        self._assert_content(message, invoice)
        self.assertIn("N/A", stored_message(message).body_html or "")

    def test_existing_flat_facade_renders_real_values_with_the_actual_seed(self) -> None:
        invoice = self._create_invoice()
        sent = EmailService.send_invoice_created(invoice)
        self.assertTrue(sent.success, sent.error)
        self.assertIsNotNone(sent.email_log_id)
        assert sent.email_log_id is not None
        message = EmailLog.objects.get(pk=sent.email_log_id)
        self.assertEqual(message.template_key, "invoice_issued")
        self._assert_queued(message)
        self._assert_content(message, invoice)

    def test_public_issue_renders_recorded_amount_and_dates(self) -> None:
        invoice = self._create_invoice()
        invoice.issued_at = datetime(2026, 1, 1, 23, 30, tzinfo=UTC)
        invoice.due_at = invoice.issued_at + timedelta(days=12)
        self._issue(invoice)
        message = self._assert_identity("invoice_issued", invoice)
        self._assert_content(message, invoice)
        html = stored_message(message).body_html or ""
        assert invoice.issued_at is not None
        self.assertIn(timezone.localtime(invoice.issued_at).strftime("%Y-%m-%d"), html)
        self.assertIn(timezone.localtime(invoice.due_at).strftime("%Y-%m-%d"), html)
        self.assertEqual(message.priority, "high")

    def test_public_payment_success_renders_the_invoice_receipt(self) -> None:
        invoice = self._create_invoice()
        self._issue(invoice)
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=invoice.total_cents,
            payment_method="bank",
        )
        payment.succeed()
        payment.save()
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "paid")
        message = self._assert_identity("payment_received", invoice)
        self.assertEqual(message.priority, "normal")

    def test_public_overdue_transition_renders_recorded_days(self) -> None:
        invoice = self._create_invoice()
        invoice.issued_at = timezone.now() - timedelta(days=5)
        invoice.due_at = timezone.now() - timedelta(days=3, minutes=1)
        self._issue(invoice)
        invoice.mark_overdue()
        invoice.save()
        message = self._assert_identity("invoice_overdue", invoice)
        self.assertIn("3 days", stored_message(message).body_html or "")
        self.assertEqual(message.priority, "high")

    def test_public_void_transition_renders_the_document_identity(self) -> None:
        invoice = self._create_invoice()
        invoice.void()
        invoice.save()
        message = self._assert_identity("invoice_voided", invoice)
        self.assertEqual(message.priority, "normal")

    def test_external_draft_uses_pending_display_without_allocating_a_number(self) -> None:
        template = EmailTemplate.objects.get(key="invoice_created", locale="en")
        template.body_html += "|link={{invoice_url}}|due={{due_date}}"
        template.save()
        cache.clear()
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            issuer_provider=ISSUER_SMARTBILL,
            number=None,
            bill_to_name=self.customer.get_display_name(),
            bill_to_email=self.customer.primary_email,
            subtotal_cents=10000,
            total_cents=10000,
        )
        self.assertIsNone(Invoice.objects.get(pk=invoice.pk).number)
        message = self._assert_identity("invoice_created", invoice)
        self.assertIn("|link=|due=N/A", stored_message(message).body_html or "")

    def test_custom_created_template_retains_models_and_live_line_queryset(self) -> None:
        template = EmailTemplate.objects.get(key="invoice_created", locale="en")
        template.subject = "Custom {{invoice.number}}"
        template.body_html = "{{customer.company_name}}|{{invoice.total}}|{{invoice_lines.count}}"
        template.save()
        cache.clear()
        invoice = self._create_invoice()
        message = EmailLog.objects.get(template_key="invoice_created", to_addr=invoice.bill_to_email)
        self._assert_queued(message)
        self.assertEqual(
            stored_message(message).body_html,
            f"{self.customer.company_name}|{invoice.total}|0",
            "Initial creation runs before line insertion; do not fabricate or defer line contents",
        )
        self.assertEqual(invoice.lines.count(), 1)

    def test_non_status_update_does_not_publish_another_invoice_message(self) -> None:
        invoice = self._create_invoice()
        messages = set(EmailLog.objects.values_list("pk", flat=True))
        tasks = set(OrmQ.objects.values_list("pk", flat=True))
        invoice.meta = {**invoice.meta, "email_content_control": True}
        invoice.save(update_fields=["meta"])
        self.assertEqual(set(EmailLog.objects.values_list("pk", flat=True)), messages)
        self.assertEqual(set(OrmQ.objects.values_list("pk", flat=True)), tasks)

    def test_rolled_back_invoice_publishes_no_message_or_task(self) -> None:
        initial_tasks = OrmQ.objects.count()
        with transaction.atomic():
            self._create_invoice()
            self.assertTrue(EmailLog.objects.filter(template_key="invoice_created").exists())
            transaction.set_rollback(True)
        self.assertFalse(Invoice.objects.exists())
        self.assertFalse(EmailLog.objects.filter(template_key="invoice_created").exists())
        self.assertEqual(OrmQ.objects.count(), initial_tasks)
