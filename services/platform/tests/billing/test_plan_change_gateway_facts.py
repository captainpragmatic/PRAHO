"""Authenticated gateway facts must still identify this exact payable plan attempt."""

from uuid import uuid4

from django.test import TestCase

from apps.billing.models import Payment, ProformaInvoice
from apps.billing.payment_convergence import PaymentSuccessService
from tests.billing.test_plan_change_models import _PlanChangeFixture


class PlanChangeGatewayFactsTests(_PlanChangeFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.change_row = self.change()
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency, number="FACTS-PLAN", subtotal_cents=6000, total_cents=6000
        )
        self.attempt_id = str(uuid4())
        self.payment = Payment.objects.create(
            customer=self.customer,
            proforma=self.proforma,
            currency=self.currency,
            amount_cents=6000,
            payment_method="stripe",
            meta={
                "source": "hosting_plan_change",
                "plan_change_id": str(self.change_row.pk),
                "plan_change_attempt_id": self.attempt_id,
                "quote_fingerprint": self.change_row.request_fingerprint,
            },
        )
        self.metadata = {
            "platform": "PRAHO",
            "source": "hosting_plan_change",
            "customer_id": str(self.customer.pk),
            "payment_id": str(self.payment.pk),
            "plan_change_id": str(self.change_row.pk),
            "attempt_id": self.attempt_id,
            "proforma_id": str(self.proforma.pk),
            "quote_fingerprint": self.change_row.request_fingerprint,
        }

    def facts(self, metadata=None):
        return {
            "amount_received": 6000,
            "currency": "ron",
            "customer_id": None,
            "metadata": self.metadata if metadata is None else metadata,
        }

    def test_exact_original_document_owner_and_attempt_are_accepted(self) -> None:
        self.assertIsNone(PaymentSuccessService._validate_gateway_facts(self.payment, self.facts()))

    def test_matching_amount_does_not_authorize_other_document_owner_or_attempt(self) -> None:
        for key in self.metadata:
            with self.subTest(key=key):
                facts = self.facts({**self.metadata, key: "another-value"})
                self.assertIsNotNone(PaymentSuccessService._validate_gateway_facts(self.payment, facts))

    def test_missing_metadata_and_saved_customer_are_refused(self) -> None:
        self.assertIsNotNone(PaymentSuccessService._validate_gateway_facts(self.payment, self.facts({})))
        facts = self.facts()
        facts["customer_id"] = "cus_saved_unexpected"
        self.assertIsNotNone(PaymentSuccessService._validate_gateway_facts(self.payment, facts))
