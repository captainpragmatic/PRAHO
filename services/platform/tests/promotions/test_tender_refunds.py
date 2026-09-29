"""Split refunds restore each original tender once, including after gateway failure."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.invoice_models import Invoice
from apps.billing.issuers.service import _split_correction_refusal
from apps.billing.models import Currency, Payment, Refund
from apps.billing.refund_service import RefundReason, RefundService, RefundType
from apps.customers.models import Customer
from apps.promotions import tender_refunds
from apps.promotions.gift_cards import pay_document
from apps.promotions.models import GiftCard, GiftCardTransaction
from apps.promotions.tender_refunds import refund_document


class TenderRefundTests(TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Leu", "symbol": "lei"})
        self.customer = Customer.objects.create(name="Split buyer", customer_type="individual")
        self.card = GiftCard.objects.create(
            code="EXISTING-BALANCE",
            currency=self.currency,
            initial_value_cents=5000,
            current_balance_cents=5000,
            status="active",
            ledger_version=2,
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-SPLIT",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        self.invoice.issue()
        self.invoice.save()
        pay_document(self.card.code, self.invoice, self.customer, "pay-gift", 5000)
        self.cash = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=7100,
            payment_method="stripe",
            gateway_txn_id="pi_original_cash",
            status="succeeded",
        )
        self.invoice.mark_as_paid()
        self.invoice.save()

    def gateway_result(self, amount: int, refund_id: str = "re_split") -> dict:
        return {"success": True, "refund_id": refund_id, "status": "succeeded", "amount_refunded_cents": amount}

    def test_existing_refund_api_accepts_typed_full_refund(self):

        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = self.gateway_result(7100)
            result = RefundService.refund_invoice(
                self.invoice.pk,
                {
                    "refund_type": RefundType.FULL,
                    "reason": RefundReason.CUSTOMER_REQUEST,
                    "idempotency_key": "typed-full",
                },
            )
        self.assertTrue(result.is_ok(), result)
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "refunded")

    def test_partial_and_final_refunds_reconcile_original_tenders_and_preserve_vat(self) -> None:
        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = self.gateway_result(3550)
            first = refund_document(self.invoice.pk, 6050, "partial-1", reason="customer_request")
            replay = refund_document(self.invoice.pk, 6050, "partial-1", reason="customer_request")
            self.assertEqual(first.pk, replay.pk)
            factory.return_value.refund_payment.assert_called_once()
            self.assertEqual(first.status, "completed")
            self.card.refresh_from_db()
            self.assertEqual(self.card.current_balance_cents, 2500)
            factory.return_value.refund_payment.return_value = self.gateway_result(3550, "re_split_final")
            second = refund_document(self.invoice.pk, 6050, "partial-2", reason="customer_request")
        self.assertEqual(second.status, "completed")
        self.card.refresh_from_db()
        self.invoice.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 5000)
        self.assertEqual(
            (self.invoice.subtotal_cents, self.invoice.tax_cents, self.invoice.total_cents), (10000, 2100, 12100)
        )
        self.assertEqual(self.invoice.status, "refunded")
        self.assertEqual(
            sum(Refund.objects.filter(invoice=self.invoice, status="completed").values_list("amount_cents", flat=True)),
            12100,
        )

    def test_retry_does_not_restore_gift_balance_twice(self) -> None:
        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.side_effect = TimeoutError("lost response")
            first = refund_document(self.invoice.pk, 12100, "full-retry", reason="customer_request")
            self.assertEqual(first.status, "failed")
            failed_leg = first.legs.get(payment=self.cash)
            for record in (first, failed_leg):
                self.assertEqual(AuditEvent.objects.filter(
                    object_id=str(record.pk), content_type__model=record._meta.model_name,
                    new_values__status="failed",
                ).count(), 1)
            self.card.refresh_from_db()
            self.assertEqual(self.card.current_balance_cents, 5000)
            first_key = factory.return_value.refund_payment.call_args.kwargs["idempotency_key"]
            factory.return_value.refund_payment.side_effect = None
            factory.return_value.refund_payment.return_value = self.gateway_result(7100)
            second = refund_document(self.invoice.pk, 12100, "full-retry", reason="customer_request")
            self.assertEqual(factory.return_value.refund_payment.call_args.kwargs["idempotency_key"], first_key)
        self.assertEqual(second.status, "completed")
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 5000)
        self.assertEqual(GiftCardTransaction.objects.filter(gift_card=self.card, transaction_type="refund").count(), 1)

    def test_staff_can_resume_from_reloaded_invoice_and_customer_cannot(self):
        staff = get_user_model().objects.create_user(email="refund-staff@example.test", staff_role="billing")
        customer_user = get_user_model().objects.create_user(email="refund-customer@example.test")
        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.side_effect = TimeoutError("lost response")
            command = refund_document(self.invoice.pk, 12100, "staff-resume", reason="customer_request", actor=staff)
            url = reverse("billing:invoice_refund_retry", kwargs={"pk": self.invoice.pk, "command_id": command.pk})
            self.client.force_login(customer_user)
            denied = self.client.post(url)
            self.assertEqual(denied.status_code, 403)
            self.client.force_login(staff)
            detail = self.client.get(reverse("billing:invoice_detail", kwargs={"pk": self.invoice.pk}))
            self.assertContains(detail, "Resume refund")
            self.assertContains(detail, url)
            factory.return_value.refund_payment.side_effect = None
            factory.return_value.refund_payment.return_value = self.gateway_result(7100)
            response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        command.refresh_from_db()
        self.assertEqual(command.status, "completed")
        self.assertEqual(GiftCardTransaction.objects.filter(gift_card=self.card, transaction_type="refund").count(), 1)

    def test_aged_local_tenders_can_resume_once_without_a_gateway(self):
        self.cash.payment_method = "bank"
        self.cash.save(update_fields=["payment_method"])
        command = tender_refunds._reserve_command(self.invoice.pk, 12100, "aged", "customer_request", None)
        Refund.objects.filter(tender_leg__command=command).update(
            created_at=timezone.now() - timezone.timedelta(days=2)
        )
        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            result = tender_refunds._run_command(command)
            tender_refunds._run_command(result)
            factory.assert_not_called()
        self.assertEqual(result.status, "completed")
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 5000)
        self.assertEqual(GiftCardTransaction.objects.filter(gift_card=self.card, transaction_type="refund").count(), 1)

    def test_aged_uncertain_gateway_tender_still_requires_reconciliation(self):
        command = tender_refunds._reserve_command(self.invoice.pk, 12100, "aged-gateway", "customer_request", None)
        Refund.objects.filter(tender_leg__command=command).update(
            created_at=timezone.now() - timezone.timedelta(days=2)
        )
        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            result = tender_refunds._run_command(command)
            factory.assert_not_called()
        self.assertEqual(result.status, "failed")
        self.assertIn("reconciliation", result.legs.get(payment=self.cash).error)
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 5000)

    def test_over_refund_and_changed_retry_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            refund_document(self.invoice.pk, 12101, "too-much", reason="customer_request")
        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = self.gateway_result(3550)
            refund_document(self.invoice.pk, 6050, "stable", reason="customer_request")
        with self.assertRaises(ValidationError):
            refund_document(self.invoice.pk, 6051, "stable", reason="customer_request")

    def test_one_full_split_refund_is_one_accounting_correction(self):

        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = self.gateway_result(7100)
            refund_document(self.invoice.pk, 12100, "full-accounting", reason="customer_request")
        self.invoice.refresh_from_db()
        self.assertIsNone(_split_correction_refusal(self.invoice))

    def test_gateway_success_survives_failed_local_projection(self) -> None:

        original = tender_refunds._project_leg

        def fail_cash_projection(leg, invoice):
            if leg.payment_id == self.cash.pk:
                raise ValidationError("Local projection temporarily unavailable")
            return original(leg, invoice)

        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = self.gateway_result(7100)
            with patch("apps.promotions.tender_refunds._project_leg", side_effect=fail_cash_projection):
                command = refund_document(self.invoice.pk, 12100, "projection-retry", reason="customer_request")
            cash_refund = command.legs.get(payment=self.cash).refund
            self.assertEqual((cash_refund.status, cash_refund.gateway_refund_id), ("completed", "re_split"))
            command = refund_document(self.invoice.pk, 12100, "projection-retry", reason="customer_request")
            factory.return_value.refund_payment.assert_called_once()
        self.assertEqual(command.status, "completed")
