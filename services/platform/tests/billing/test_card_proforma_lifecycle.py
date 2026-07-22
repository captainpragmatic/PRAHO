"""
Tests for Phase 5: Card Payment → Proforma → Invoice Lifecycle (TDD RED phase).

These tests describe the behaviour after the Phase 1-3 production changes are applied:
  - Phase 1: create_payment_intent_direct() sets Payment.proforma
  - Phase 2: confirm_order endpoint converts proforma when webhook hasn't arrived
  - Phase 3: fallback task routes through proforma path when proforma+succeeded payment exist

All tests use the ProformaLifecycleTestBase pattern for consistent setup.
They may fail on the current codebase (expected — TDD RED) and should pass
once the Phase 1-3 changes are applied.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.billing.gateways.base import PaymentConfirmResult
from apps.billing.models import Currency
from apps.billing.payment_models import Payment
from apps.billing.proforma_models import ProformaInvoice, ProformaSequence
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.provisioning.models import ServicePlan
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status

# ===============================================================================
# SHARED TEST BASE
# ===============================================================================


class CardProformaTestBase(TestCase):
    """Base test case with order/proforma/payment helpers for card-payment tests."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Card Test SRL",
            customer_type="company",
            status="active",
            primary_email="card@test.ro",
            company_name="Card Test SRL",
        )
        self.product = Product.objects.create(
            name="Shared Hosting Basic",
            slug="card-test-hosting",
            product_type="shared_hosting",
            is_active=True,
        )
        self.service_plan = ServicePlan.objects.create(
            name="Card Test Shared Hosting",
            plan_type="shared_hosting",
            price_monthly=Decimal("100.00"),
        )
        self.product.default_service_plan = self.service_plan
        self.product.save(update_fields=["default_service_plan"])
        self.user = User.objects.create_user(
            email="admin-card@pragmatichost.com",
            password="testpass123",
            is_staff=True,
        )
        ProformaSequence.objects.get_or_create(scope="default")
        self.factory = APIRequestFactory()

    def _create_order_with_items(self, total_cents: int = 12100, **kwargs: object) -> Order:
        """Create an order with a single OrderItem (mirrors ProformaLifecycleTestBase)."""
        defaults: dict = {
            "customer": self.customer,
            "currency": self.currency,
            "customer_email": self.customer.primary_email,
            "customer_name": self.customer.name,
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": total_cents,
            "billing_address": {"company_name": "Card Test SRL", "country": "RO"},
        }
        defaults.update(kwargs)
        order = Order.objects.create(**defaults)
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return order

    def _create_sent_proforma_for_order(self, order: Order) -> ProformaInvoice:
        """Create a sent proforma linked to an order (simulates awaiting_payment signal)."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        result = ProformaService.create_from_order(order)
        if result.is_err():
            self.fail(f"Failed to create proforma: {result.unwrap_err()}")
        proforma = result.unwrap()
        # Advance to sent so record_payment_and_convert accepts it
        proforma.send_proforma()
        proforma.save()
        order.refresh_from_db()
        return proforma

    def _create_pending_payment(
        self, gateway_txn_id: str, proforma: ProformaInvoice | None = None
    ) -> Payment:
        """Create a pending Payment record, optionally linked to a proforma."""
        return Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=12100,
            payment_method="stripe",
            gateway_txn_id=gateway_txn_id,
            proforma=proforma,
            meta={"proforma_id": str(proforma.id)} if proforma else {},
        )

    def _make_confirm_request(
        self, data: dict, portal_authenticated: bool = True
    ) -> object:
        """Build a POST request for the confirm_order API endpoint."""
        request = self.factory.post(
            "/api/orders/confirm/",
            data=data,
            content_type="application/json",
        )
        setattr(request, "_portal_authenticated", portal_authenticated)  # noqa: B010
        request.user = self.user
        return request


# ===============================================================================
# TEST 5.1: create_payment_intent_direct links Payment to proforma
# ===============================================================================


class TestCreatePaymentIntentDirectLinksProforma(CardProformaTestBase):
    """Phase 1 verification: create_payment_intent_direct() must link Payment.proforma."""

    @patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway")
    def test_payment_proforma_fk_set_when_order_has_proforma(self, mock_create_gateway: MagicMock) -> None:
        """When order is in awaiting_payment (proforma exists), Payment.proforma must be linked.

        Phase 1 fix: Payment.objects.create() must pass proforma=order.proforma so the
        Stripe webhook can later call record_payment_and_convert() automatically.
        """
        mock_gateway = MagicMock()
        mock_gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_proforma_link_test1",
            "client_secret": "cs_test1",
        }
        mock_create_gateway.return_value = mock_gateway

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        order.refresh_from_db()
        self.assertIsNotNone(order.proforma, "Proforma must be linked to order before calling create_payment_intent_direct")

        from apps.billing.payment_service import PaymentService  # noqa: PLC0415

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(order.customer.id),
            amount_cents=order.total_cents,
            currency="RON",
            gateway="stripe",
        )

        self.assertTrue(result.get("success"), f"Expected success=True, got: {result}")

        payment = Payment.objects.get(gateway_txn_id="pi_proforma_link_test1")
        self.assertEqual(
            payment.proforma_id,
            proforma.id,
            "Payment.proforma must be linked to the order's proforma (Phase 1 fix)",
        )

    @patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway")
    def test_payment_meta_contains_proforma_id(self, mock_create_gateway: MagicMock) -> None:
        """Payment.meta must include proforma_id for B-1 savepoint-rollback recovery.

        If the savepoint that writes payment.proforma rolls back (e.g., OOM), the
        meta['proforma_id'] field allows the webhook retry to re-link the proforma
        and attempt conversion.
        """
        mock_gateway = MagicMock()
        mock_gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_meta_proforma_test2",
            "client_secret": "cs_test2",
        }
        mock_create_gateway.return_value = mock_gateway

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        order.refresh_from_db()

        from apps.billing.payment_service import PaymentService  # noqa: PLC0415

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(order.customer.id),
            amount_cents=order.total_cents,
            currency="RON",
            gateway="stripe",
        )
        self.assertTrue(result.get("success"))

        payment = Payment.objects.get(gateway_txn_id="pi_meta_proforma_test2")
        self.assertIn(
            "proforma_id",
            payment.meta,
            "payment.meta must contain 'proforma_id' for B-1 recovery",
        )
        self.assertEqual(
            payment.meta["proforma_id"],
            str(proforma.id),
            "payment.meta['proforma_id'] must match the order's proforma",
        )

    @patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway")
    def test_no_proforma_with_nonzero_total_fails_closed(
        self, mock_create_gateway: MagicMock
    ) -> None:
        """A positive order must have an authoritative proforma before Stripe is called."""

        # Order in draft — no proforma exists yet
        order = self._create_order_with_items()
        self.assertIsNone(order.proforma, "Precondition: order must have no proforma")

        from apps.billing.payment_service import PaymentService  # noqa: PLC0415

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(order.customer.id),
            amount_cents=order.total_cents,
            currency="RON",
            gateway="stripe",
        )

        self.assertFalse(result.get("success"))
        self.assertIn("authoritative proforma", result.get("error", ""))
        self.assertFalse(Payment.objects.exists())
        mock_create_gateway.assert_not_called()


# ===============================================================================
# TEST 5.2: Stripe webhook converts proforma for card payment
# ===============================================================================


class TestWebhookConvertsProformaForCardPayment(CardProformaTestBase):
    """Phase 1+webhook verification: when Payment.proforma is set, the webhook converts it."""

    def _get_processor(self) -> object:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        return StripeWebhookProcessor()

    def _build_succeeded_payload(self, stripe_payment_id: str) -> dict:
        return {
            "data": {
                "object": {
                    "id": stripe_payment_id,
                    "payment_method": "pm_test",
                    "amount_received": 12100,
                    "currency": "ron",
                },
            },
        }

    @patch("apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert")
    def test_webhook_calls_record_payment_and_convert_when_proforma_linked(
        self, mock_convert: MagicMock
    ) -> None:
        """When payment.proforma is set (Phase 1 fix), webhook triggers proforma conversion.

        This test verifies the integration between the Phase 1 fix (proforma linking)
        and the existing webhook handler. The webhook handler already checks
        `if payment.proforma:` — once Phase 1 populates that FK, this block fires.
        """
        from apps.common.types import Ok  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)

        # Create payment WITH proforma linked (state after Phase 1 fix)
        payment = self._create_pending_payment("pi_testWebhookConv52abc", proforma=proforma)
        force_status(payment, "succeeded")

        mock_convert.return_value = Ok(MagicMock())

        processor = self._get_processor()
        payload = self._build_succeeded_payload("pi_testWebhookConv52abc")
        success, _msg = processor.handle_payment_intent_event("payment_intent.succeeded", payload)

        self.assertTrue(success, f"Webhook must succeed when proforma conversion succeeds: {_msg}")
        mock_convert.assert_called_once()
        call_kwargs = mock_convert.call_args[1] if mock_convert.call_args[1] else {}
        call_args = mock_convert.call_args[0] if mock_convert.call_args[0] else ()
        # Accept both positional and keyword call forms
        called_proforma_id = call_kwargs.get("proforma_id") or (call_args[0] if call_args else None)
        self.assertEqual(
            called_proforma_id,
            str(proforma.id),
            "Webhook must call record_payment_and_convert with the correct proforma_id",
        )

    def test_webhook_without_proforma_does_not_call_conversion(self) -> None:
        """Payment without proforma FK must NOT trigger proforma conversion (no regression).

        This test guards against calling record_payment_and_convert for payments that
        have no proforma (e.g., admin-created payments before the Phase 1 fix, or
        manually-created test payments).
        """
        payment = self._create_pending_payment("pi_testWebhookNoPfm52xy")
        force_status(payment, "succeeded")
        self.assertIsNone(payment.proforma, "Precondition: payment must have no proforma")

        with patch(
            "apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert"
        ) as mock_convert:
            processor = self._get_processor()
            payload = self._build_succeeded_payload("pi_testWebhookNoPfm52xy")
            # No assertion on success here — focus is on conversion NOT being called
            processor.handle_payment_intent_event("payment_intent.succeeded", payload)

        mock_convert.assert_not_called()


# ===============================================================================
# TEST 5.3: confirm_order converts proforma when webhook hasn't arrived
# ===============================================================================


class TestConfirmOrderConvertsProformaBeforeWebhook(CardProformaTestBase):
    """Phase 2 verification: confirm_order endpoint converts proforma when webhook hasn't arrived."""

    def test_confirm_order_converts_proforma_and_confirms_order(self) -> None:
        """Synchronous fallback: confirm_order converts proforma when webhook is delayed.

        Scenario: customer pays by card, Stripe webhook fires AFTER the customer calls
        confirm_order. The endpoint must detect order.proforma (no invoice yet) and
        call ProformaPaymentService.record_payment_and_convert() itself, then confirm the order.

        After Phase 2 fix:
        - order.invoice is set (proforma converted)
        - order.status is paid/provisioning/in_review (not awaiting_payment)
        - proforma.status == "converted"
        """
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        order.refresh_from_db()

        payment = self._create_pending_payment("pi_testConfirmPfm53abcd", proforma=proforma)
        force_status(payment, "succeeded")

        # Save PI to order (as Phase 1 would during create_payment_intent_direct)
        order.payment_intent_id = "pi_testConfirmPfm53abcd"
        order.payment_method = "card"
        order.save(update_fields=["payment_intent_id", "payment_method"])

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=12100,
            currency="ron",
        )

        request = self._make_confirm_request({"payment_intent_id": "pi_testConfirmPfm53abcd"})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(
            response.status_code,
            200,
            f"confirm_order must return 200 after proforma conversion, got {response.status_code}: {response.data}",
        )
        self.assertTrue(response.data.get("success"), f"Expected success=True: {response.data}")

        order.refresh_from_db()
        self.assertIn(
            order.status,
            ["paid", "provisioning", "in_review"],
            f"Order must advance from awaiting_payment after proforma conversion, got: {order.status}",
        )

        proforma.refresh_from_db()
        self.assertEqual(
            proforma.status,
            "converted",
            "Proforma must be converted by the confirm_order endpoint",
        )

        order.refresh_from_db()
        self.assertIsNotNone(
            order.invoice,
            "Order.invoice must be set after proforma-to-invoice conversion",
        )
        payment.refresh_from_db()
        self.assertEqual(payment.meta["stripe_amount_received"], 12100)
        self.assertEqual(payment.meta["stripe_currency"], "ron")

    @patch("apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert")
    def test_confirm_order_passes_frozen_proforma_total_after_order_drift(self, mock_convert: MagicMock) -> None:
        from apps.api.orders.views import confirm_order  # noqa: PLC0415
        from apps.common.types import Ok  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        payment = self._create_pending_payment("pi_testOrderDrift53", proforma=proforma)
        order.total_cents = proforma.total_cents + 100
        order.payment_intent_id = payment.gateway_txn_id
        order.payment_method = "card"
        order.save(update_fields=["total_cents", "payment_intent_id", "payment_method"])
        order.refresh_from_db()
        self.assertEqual(order.status, "awaiting_payment")

        mock_convert.return_value = Ok(MagicMock())
        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=proforma.total_cents,
            currency="ron",
        )
        request = self._make_confirm_request({"payment_intent_id": payment.gateway_txn_id})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
            patch(
                "apps.billing.payment_convergence.PaymentSuccessService.converge_gateway_success",
                return_value=Ok(payment),
            ),
            patch("apps.orders.services.OrderPaymentConfirmationService.confirm_order", return_value=Ok(order)),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(mock_convert.call_args.kwargs["amount_cents"], proforma.total_cents)

    @patch("apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert")
    def test_confirm_order_rejects_proforma_drift_after_stripe_verification(self, mock_convert: MagicMock) -> None:
        from apps.api.orders.views import confirm_order  # noqa: PLC0415
        from apps.common.types import Ok  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        verified_total_cents = proforma.total_cents
        payment = self._create_pending_payment("pi_testProformaDrift53", proforma=proforma)
        order.payment_intent_id = payment.gateway_txn_id
        order.payment_method = "card"
        order.save(update_fields=["payment_intent_id", "payment_method"])
        order.refresh_from_db()
        self.assertEqual(order.status, "awaiting_payment")

        def confirm_then_drift(_payment_intent_id: str) -> PaymentConfirmResult:
            ProformaInvoice.objects.filter(pk=proforma.pk).update(total_cents=verified_total_cents + 100)
            return PaymentConfirmResult(
                success=True,
                status="succeeded",
                error=None,
                amount_received=verified_total_cents,
                currency="ron",
            )

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.side_effect = confirm_then_drift
        mock_convert.return_value = Ok(MagicMock())
        request = self._make_confirm_request({"payment_intent_id": payment.gateway_txn_id})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
            patch(
                "apps.billing.payment_convergence.PaymentSuccessService.converge_gateway_success",
                return_value=Ok(payment),
            ),
            patch("apps.orders.services.OrderPaymentConfirmationService.confirm_order", return_value=Ok(order)),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 409)
        self.assertIn("changed after payment verification", response.data["error"])
        mock_convert.assert_not_called()

    def test_confirm_order_invoice_linked_to_order_after_conversion(self) -> None:
        """After confirm_order converts the proforma, order.invoice must be the new invoice.

        The invoice created from proforma conversion must be linked back to the order
        so billing staff can find it without querying payments.
        """
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        order.refresh_from_db()

        payment = self._create_pending_payment("pi_testInvLink53bdefgh", proforma=proforma)
        force_status(payment, "succeeded")

        order.payment_intent_id = "pi_testInvLink53bdefgh"
        order.payment_method = "card"
        order.save(update_fields=["payment_intent_id", "payment_method"])

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=12100,
            currency="ron",
        )

        request = self._make_confirm_request({"payment_intent_id": "pi_testInvLink53bdefgh"})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 200, f"Expected 200, got: {response.data}")
        order.refresh_from_db()
        self.assertIsNotNone(order.invoice, "order.invoice must be set after confirm_order")
        self.assertEqual(
            order.invoice.status,
            "paid",
            "Converted invoice must be in paid status",
        )


# ===============================================================================
# TEST 5.4: confirm_order idempotent when webhook already converted
# ===============================================================================


class TestConfirmOrderIdempotentAfterWebhook(CardProformaTestBase):
    """Phase 2 verification: confirm_order is idempotent when webhook already converted proforma."""

    def test_confirm_order_returns_409_when_order_already_paid(self) -> None:
        """confirm_order returns 409 when webhook has already confirmed the order.

        The Phase 3 transaction re-checks order.status. If the webhook beat the
        confirm_order endpoint and advanced the order to paid/provisioning, Phase 3
        detects this and returns 409 — no double-confirm, no duplicate invoice.
        """
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        order.refresh_from_db()

        payment = self._create_pending_payment("pi_testIdempotent54xyz1", proforma=proforma)
        force_status(payment, "succeeded")

        order.payment_intent_id = "pi_testIdempotent54xyz1"
        order.payment_method = "card"
        order.save(update_fields=["payment_intent_id", "payment_method"])

        # Simulate webhook already advancing the order to paid
        force_status(order, "paid")

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True, status="succeeded", error=None, amount_received=12100,
        )

        request = self._make_confirm_request({"payment_intent_id": "pi_testIdempotent54xyz1"})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
        ):
            response = confirm_order(request, str(order.id))

        # CODEX-8 fix: idempotent — already-confirmed orders return 200 (not 409)
        self.assertEqual(
            response.status_code,
            200,
            f"confirm_order must return 200 (idempotent) when order was already confirmed: {response.data}",
        )
        self.assertTrue(response.data.get("success"))

    def test_confirm_order_no_error_when_proforma_already_converted(self) -> None:
        """confirm_order must succeed even if proforma is already converted (webhook first).

        In the race where webhook runs first (converts proforma → order.invoice set,
        order advanced to paid) but confirm_order was already past Phase 2 (Stripe
        verification done), Phase 3 detects order.status != awaiting_payment and
        returns 409. This is correct idempotent behaviour — not an error state.

        This test verifies the service-layer idempotency path separately:
        calling OrderPaymentConfirmationService.confirm_order on a paid order returns Ok.
        """
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "paid")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(
            result.is_ok(),
            f"confirm_order on already-paid order must return Ok (idempotent), got: {result}",
        )


# ===============================================================================
# TEST 5.5: Fallback task uses proforma path when proforma + succeeded payment exist
# ===============================================================================


class TestFallbackTaskUsesProformaPath(CardProformaTestBase):
    """Phase 3 verification: fallback task routes through proforma conversion when applicable."""

    def test_task_uses_positive_proforma_when_order_total_drifted_to_zero(self) -> None:
        """A frozen positive proforma must never be dispatched as a free order."""
        from apps.orders.tasks import process_pending_orders  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        self._create_sent_proforma_for_order(order)
        order.total_cents = 0
        order.save(update_fields=["total_cents"])

        with (
            patch("apps.orders.tasks._convert_proforma_or_create_invoice") as mock_convert,
            patch("apps.orders.tasks._process_free_order") as mock_free,
        ):
            result = process_pending_orders()

        self.assertTrue(result["success"])
        mock_convert.assert_called_once()
        mock_free.assert_not_called()

    def test_task_calls_record_payment_and_convert_for_proforma_order(self) -> None:
        """When order has proforma + succeeded payment, fallback task converts via proforma path.

        Phase 3: _convert_proforma_or_create_invoice() detects (order.proforma exists AND
        a succeeded Payment is linked) and calls ProformaPaymentService.record_payment_and_convert()
        instead of InvoiceService.create_from_order() directly.

        This ensures ALL orders — including those where the webhook was delayed —
        follow the canonical proforma→invoice path required by Romanian tax law.
        """
        from apps.orders.tasks import _convert_proforma_or_create_invoice  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        order.refresh_from_db()

        payment = self._create_pending_payment("pi_testFallbackTask55ab", proforma=proforma)
        force_status(payment, "succeeded")
        order.total_cents = proforma.total_cents + 100
        order.save(update_fields=["total_cents"])

        order_result: dict = {}
        results: dict = {"errors": []}

        with patch(
            "apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert"
        ) as mock_convert:
            from apps.common.types import Ok  # noqa: PLC0415

            mock_convert.return_value = Ok(MagicMock())
            _convert_proforma_or_create_invoice(order, order_result, results)

        mock_convert.assert_called_once()
        call_kwargs = mock_convert.call_args[1] if mock_convert.call_args else {}
        called_proforma_id = call_kwargs.get("proforma_id")
        self.assertEqual(
            called_proforma_id,
            str(proforma.id),
            "Fallback task must call record_payment_and_convert with the correct proforma_id",
        )
        self.assertEqual(call_kwargs.get("amount_cents"), proforma.total_cents)
        self.assertEqual(results["errors"], [], f"Task must not produce errors: {results['errors']}")

    def test_task_creates_proforma_first_when_missing(self) -> None:
        """When order has NO proforma but has succeeded payment, task creates proforma then converts.

        Edge case: signal failed during draft→awaiting_payment transition (e.g., DB hiccup).
        The fallback task should create the missing proforma, then convert it using the
        existing succeeded payment.
        """
        from apps.orders.tasks import process_pending_orders  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        # Deliberately do NOT create a proforma — simulates signal failure
        self.assertIsNone(order.proforma, "Precondition: order must have no proforma")

        payment = self._create_pending_payment("pi_testMissingPfm55bcde")
        force_status(payment, "succeeded")

        # Run the full fallback task — it should create the proforma and route through it
        with (
            patch("django_q.tasks.async_task"),
            patch("django.core.cache.cache.add", return_value=True),
            patch("django.core.cache.cache.delete"),
        ):
            task_result = process_pending_orders()

        self.assertTrue(
            task_result.get("success", False),
            f"process_pending_orders must succeed: {task_result}",
        )

        order.refresh_from_db()
        self.assertIsNotNone(
            order.proforma,
            "Fallback task must create a proforma for orders missing one",
        )

    def test_task_skips_proforma_conversion_when_no_succeeded_payment(self) -> None:
        """When proforma exists but no succeeded payment, task must NOT convert.

        An order in awaiting_payment with a proforma but only failed payments
        is still waiting for the customer to pay. The task must not call
        record_payment_and_convert — that would create an invoice without real payment.

        Phase 3: _convert_proforma_or_create_invoice() checks for a succeeded Payment before
        routing through the proforma path. With only a failed payment, it should log
        and skip — order stays in awaiting_payment for the next cycle.
        """
        from apps.orders.tasks import _convert_proforma_or_create_invoice  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma = self._create_sent_proforma_for_order(order)
        order.refresh_from_db()

        # Create only a FAILED payment — no succeeded payment exists
        payment = self._create_pending_payment("pi_testFailed55cdefghij", proforma=proforma)
        force_status(payment, "failed")

        order_result: dict = {}
        results: dict = {"errors": []}

        with patch(
            "apps.billing.proforma_service.ProformaPaymentService.record_payment_and_convert"
        ) as mock_convert:
            _convert_proforma_or_create_invoice(order, order_result, results)

        # Proforma conversion must NOT be triggered — payment failed, not succeeded
        mock_convert.assert_not_called()


# ===============================================================================
# TEST 5.6: create_payment_intent_direct behaviour when order has no proforma
# ===============================================================================


class TestCreatePaymentIntentDirectNoProforma(CardProformaTestBase):
    """Fail-closed behavior when an order has no authoritative proforma."""

    @patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway")
    def test_draft_order_without_proforma_never_reaches_gateway(
        self, mock_create_gateway: MagicMock
    ) -> None:
        """Draft orders cannot bypass the billing snapshot by racing order finalization."""

        order = self._create_order_with_items()
        # Remain in draft — no proforma
        self.assertEqual(order.status, "draft", "Precondition: order must be in draft")
        self.assertIsNone(order.proforma, "Precondition: draft order has no proforma")

        from apps.billing.payment_service import PaymentService  # noqa: PLC0415

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(order.customer.id),
            amount_cents=order.total_cents,
            currency="RON",
            gateway="stripe",
        )

        self.assertFalse(result.get("success"))
        self.assertIn("authoritative proforma", result.get("error", ""))
        self.assertFalse(Payment.objects.exists())
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway")
    def test_payment_intent_succeeds_for_free_order(self, mock_create_gateway: MagicMock) -> None:
        """Free order (total=0): payment intent is not needed, but service call is safe.

        Free orders bypass the proforma flow entirely (no proforma is created for
        zero-value orders). create_payment_intent_direct should handle this gracefully
        without asserting total > 0.
        """
        mock_gateway = MagicMock()
        mock_gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_free_order_5_6b",
            "client_secret": "cs_free",
        }
        mock_create_gateway.return_value = mock_gateway

        order = self._create_order_with_items(
            total_cents=0,
            subtotal_cents=0,
            tax_cents=0,
        )
        # Adjust the order item to match zero total
        OrderItem.objects.filter(order=order).update(
            unit_price_cents=0, tax_cents=0, line_total_cents=0
        )
        Order.objects.filter(pk=order.pk).update(subtotal_cents=0, tax_cents=0, total_cents=0)
        order.refresh_from_db()
        self.assertIsNone(order.proforma, "Precondition: free order has no proforma")

        from apps.billing.payment_service import PaymentService  # noqa: PLC0415

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(order.customer.id),
            amount_cents=0,
            currency="RON",
            gateway="stripe",
        )

        self.assertFalse(result["success"])
        self.assertIn("does not require a payment", result["error"])
        mock_create_gateway.assert_not_called()
