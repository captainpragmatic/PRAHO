"""Document checkout prepares customer-present authentication without a mandate charge."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import stripe
from django.test import SimpleTestCase

from apps.billing.gateways.stripe_gateway import StripeGateway


class OnSessionDocumentGatewayTests(SimpleTestCase):
    def setUp(self) -> None:
        self.sdk = MagicMock()
        self.sdk.error.APIConnectionError = stripe.error.APIConnectionError
        self.sdk.error.APIError = stripe.error.APIError
        self.sdk.error.RateLimitError = stripe.error.RateLimitError
        self.sdk.error.StripeError = stripe.error.StripeError
        self.sdk.PaymentIntent.create.return_value = SimpleNamespace(id="pi_document", client_secret="fixture-secret")
        self.gateway = StripeGateway.__new__(StripeGateway)
        self.gateway.logger = logging.getLogger("test.document-gateway")
        self.gateway._stripe = self.sdk

    def request(self, **changes: object):
        values = {
            "document_id": "42",
            "document_type": "proforma",
            "amount_cents": 7260,
            "currency": "RON",
            "metadata": {
                "source": "hosting_plan_change",
                "customer_id": "7",
                "payment_id": "10",
                "plan_change_id": "accepted-change",
            },
            "idempotency_key": "plan-change:attempt-1",
        }
        values.update(changes)
        return self.gateway.create_on_session_document_intent(**values)

    def test_creates_unconfirmed_card_checkout_without_order_or_saved_consent(self) -> None:
        result = self.request()
        self.assertTrue(result["success"])
        self.assertEqual((result["payment_intent_id"], result["client_secret"]), ("pi_document", "fixture-secret"))
        arguments = self.sdk.PaymentIntent.create.call_args.kwargs
        self.assertEqual((arguments["amount"], arguments["currency"]), (7260, "ron"))
        self.assertIs(arguments["confirm"], False)
        self.assertEqual(arguments["payment_method_types"], ["card"])
        self.assertEqual(arguments["idempotency_key"], "plan-change:attempt-1")
        self.assertEqual(arguments["metadata"]["praho_proforma_id"], "42")
        self.assertEqual(arguments["metadata"]["payment_id"], "10")
        for key in ("off_session", "setup_future_usage", "payment_method", "customer"):
            self.assertNotIn(key, arguments)
        self.assertNotIn("praho_order_id", arguments["metadata"])

    def test_gateway_owned_binding_overrides_free_metadata(self) -> None:
        self.request(
            metadata={
                "platform": "forged",
                "praho_proforma_id": "other",
                "praho_order_id": "fake-order",
                "vat_rate": "0",
                "source": "hosting_plan_change",
            }
        )
        metadata = self.sdk.PaymentIntent.create.call_args.kwargs["metadata"]
        self.assertEqual((metadata["platform"], metadata["praho_proforma_id"]), ("PRAHO", "42"))
        self.assertNotIn("praho_order_id", metadata)
        self.assertNotIn("vat_rate", metadata)

    def test_invalid_nonpositive_or_bool_amount_never_reaches_stripe(self) -> None:
        for amount in (0, -1, True, "7260"):
            with self.subTest(amount=amount):
                self.assertFalse(self.request(amount_cents=amount)["success"])
        self.assertFalse(self.request(document_type="order")["success"])
        self.assertFalse(self.request(idempotency_key="")["success"])
        self.sdk.PaymentIntent.create.assert_not_called()

    def test_unknown_network_result_requests_recovery_with_same_key(self) -> None:
        self.sdk.PaymentIntent.create.side_effect = stripe.error.APIConnectionError("lost response")
        result = self.request()
        self.assertFalse(result["success"])
        self.assertTrue(result["retryable"])
        self.sdk.PaymentIntent.create.side_effect = None
        self.assertTrue(self.request()["success"])
        calls = self.sdk.PaymentIntent.create.call_args_list
        self.assertEqual(calls[0].kwargs, calls[1].kwargs)

    def test_invalid_request_is_definitive_without_inventing_an_intent(self) -> None:
        self.sdk.PaymentIntent.create.side_effect = stripe.error.InvalidRequestError(
            "invalid fixture request", "currency"
        )
        result = self.request()
        self.assertFalse(result["success"])
        self.assertFalse(result["retryable"])
        self.assertEqual(result["payment_intent_id"], "")

    def cancellation(self):
        return self.gateway.cancel_on_session_document_intent(
            payment_intent_id="pi_document",
            amount_cents=7260,
            currency="RON",
            metadata={"source": "hosting_plan_change", "attempt_id": "original"},
            idempotency_key="plan-cancel:original",
        )

    def test_cancellation_verifies_original_intent_and_uses_stable_key(self):
        fields = {
            "id": "pi_document",
            "amount": 7260,
            "amount_received": 0,
            "currency": "ron",
            "customer": None,
            "metadata": {"source": "hosting_plan_change", "attempt_id": "original"},
        }
        self.sdk.PaymentIntent.retrieve.return_value = SimpleNamespace(**fields, status="requires_action")
        self.sdk.PaymentIntent.cancel.return_value = SimpleNamespace(**fields, status="canceled")
        self.assertTrue(self.cancellation()["success"])
        self.sdk.PaymentIntent.cancel.assert_called_once_with("pi_document", idempotency_key="plan-cancel:original")
        for field, value in (
            ("amount", 1),
            ("currency", "usd"),
            ("id", "pi_other"),
            ("metadata", {}),
            ("customer", "cus_unexpected"),
        ):
            with self.subTest(field=field):
                self.sdk.PaymentIntent.cancel.reset_mock()
                self.sdk.PaymentIntent.retrieve.return_value = SimpleNamespace(
                    **{**fields, field: value}, status="requires_action"
                )
                self.assertFalse(self.cancellation()["success"])
                self.sdk.PaymentIntent.cancel.assert_not_called()
