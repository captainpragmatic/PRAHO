"""The staff action and locked payment service agree on eligible documents."""

from datetime import timedelta
from decimal import Decimal

from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment, ProformaInvoice, ProformaLine
from apps.billing.proforma_service import ProformaPaymentService
from apps.customers.models import Customer
from apps.users.models import User


class ManualProformaPaymentTests(TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.customer = Customer.objects.create(name="Payment UI", primary_email="payment-ui@example.test")
        self.user = User.objects.create_user(
            email="billing-ui@example.test", password="test-password", is_staff=True, staff_role="billing"
        )
        self.client.force_login(self.user)

    def document(self, status: str = "draft", *, expired: bool = False) -> ProformaInvoice:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PAY-UI-{ProformaInvoice.objects.count()}",
            valid_until=timezone.now() + timedelta(days=-1 if expired else 7),
            status=status,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        ProformaLine.objects.create(
            proforma=proforma,
            description="Hosting",
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.21"),
        )
        return proforma

    def test_eligible_states_offer_offline_payment(self) -> None:
        for status in ("draft", "sent", "accepted"):
            with self.subTest(status=status):
                document = self.document(status)
                response = self.client.get(reverse("billing:proforma_detail", args=[document.pk]))
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.context["can_record_payment"])
                self.assertContains(response, 'value="bank_transfer"')
                self.assertContains(response, 'value="cash"')
                self.assertNotContains(response, 'value="card"')

    def test_expired_and_pending_card_hide_action_and_reject_post(self) -> None:
        for pending in (False, True):
            with self.subTest(pending=pending):
                document = self.document(expired=not pending)
                if pending:
                    Payment.objects.create(
                        customer=self.customer,
                        proforma=document,
                        currency=self.currency,
                        amount_cents=document.total_cents,
                        payment_method="stripe",
                        status="pending",
                    )
                response = self.client.get(reverse("billing:proforma_detail", args=[document.pk]))
                self.assertFalse(response.context["can_record_payment"])
                self.assertTrue(response.context["payment_block_reason"])
                result = ProformaPaymentService.record_payment_and_convert(str(document.pk), 12100, "bank")
                self.assertTrue(result.is_err())
                self.assertFalse(Invoice.objects.exists())

    def test_support_cannot_record_payments(self) -> None:
        self.user.staff_role = "support"
        self.user.save(update_fields=["staff_role"])
        document = self.document()
        response = self.client.get(reverse("billing:proforma_detail", args=[document.pk]))
        self.assertFalse(response.context["can_record_payment"])
        response = self.client.post(
            reverse("billing:process_proforma_payment", args=[document.pk]), {"payment_method": "bank"}
        )
        self.assertRedirects(response, reverse("dashboard"), fetch_redirect_response=False)
        self.assertFalse(Payment.objects.exists())

    def test_payment_post_is_idempotent_and_keeps_invoice_locked(self) -> None:
        document = self.document("accepted")
        url = reverse("billing:process_proforma_payment", args=[document.pk])
        first = self.client.post(url, {"payment_method": "bank_transfer", "reference": "BANK-UI"})
        second = self.client.post(url, {"payment_method": "bank_transfer", "reference": "BANK-UI"})
        self.assertEqual(first.status_code, 302)
        self.assertEqual(first.url, second.url)
        invoice = Invoice.objects.get(converted_from_proforma=document)
        self.assertEqual(invoice.status, "paid")
        self.assertIsNotNone(invoice.locked_at)
        self.assertEqual(invoice.total_cents, 12100)
        self.assertEqual(Payment.objects.filter(proforma=document, invoice=invoice, status="succeeded").count(), 1)

    def test_card_and_missing_csrf_cannot_record_payment(self) -> None:
        document = self.document()
        url = reverse("billing:process_proforma_payment", args=[document.pk])
        response = self.client.post(url, {"payment_method": "card"})
        self.assertEqual(response.status_code, 400)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        response = csrf_client.post(url, {"payment_method": "bank"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Payment.objects.exists())
