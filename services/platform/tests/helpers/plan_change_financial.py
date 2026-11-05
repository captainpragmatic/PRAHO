"""Actual paid coverage and signed dispute events without importing TestCase modules."""

from datetime import datetime
from unittest.mock import patch

from apps.billing.models import BillingCycle, Invoice, InvoiceLine, Payment
from apps.billing.payment_convergence import PaymentSuccessService
from tests.billing.test_plan_change_intervals import _PlanChangeCoverageFixture
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture


class StripeCoverageFixture(VerifiedPlanChangeCheckoutFixture):
    def cycle(
        self, *, start: datetime | None = None, end: datetime | None = None, amount: int = 8000
    ) -> tuple[BillingCycle, Invoice, InvoiceLine]:
        cycle, invoice, line = _PlanChangeCoverageFixture.cycle(self, paid=False, start=start, end=end, amount=amount)
        Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_original_paid_coverage",
            meta={"stripe_customer_id": "cus_original_coverage"},
        )
        paid = PaymentSuccessService.converge_gateway_success(
            "pi_original_paid_coverage",
            {"amount_received": invoice.total_cents, "currency": "ron", "customer_id": "cus_original_coverage"},
        )
        self.assertTrue(paid.is_ok(), paid)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        return cycle, invoice, line

    def dispute(self, intent_id: str, *, amount: int) -> None:
        with patch("apps.notifications.services.NotificationService.send_admin_alert", return_value=True):
            accepted, message, event = self.deliver_signed_payload(
                {
                    "id": "evt_disputed_financial_coverage",
                    "type": "charge.dispute.created",
                    "data": {
                        "object": {
                            "id": "dp_visible_financial_fact",
                            "payment_intent": intent_id,
                            "amount": amount,
                            "currency": "ron",
                            "reason": "fraudulent",
                        }
                    },
                },
            )
        self.assertTrue(accepted, message)
        self.assertEqual(event.status, "processed")
        self.assertEqual(Payment.objects.get(gateway_txn_id=intent_id).status, "disputed")
