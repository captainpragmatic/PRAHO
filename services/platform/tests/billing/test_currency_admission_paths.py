"""Currency admission across document creation, recurring collection, and checkout (#103).

Every scenario exercises all five fail-closed admission sites plus the
BILLING_DEFAULT_CURRENCY system check, across EUR/USD/RON and rate states
(missing / shadowed / good / future-legacy). Only time and the external payment
gateway are mocked; FX resolution uses real rows.
"""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.core.checks import run_checks
from django.db import OperationalError
from django.test import TestCase, override_settings
from django.utils import timezone
from django.utils.translation import override

from apps.billing.currency_models import Currency, FXRate
from apps.billing.metering_models import BillingCycle
from apps.billing.payment_models import Payment
from apps.billing.payment_service import PaymentService
from apps.billing.proforma_models import ProformaInvoice, ProformaSequence
from apps.billing.proforma_service import ProformaService
from apps.billing.recurring_billing import RecurringBillingOrchestrator
from apps.billing.subscription_models import Subscription
from apps.billing.subscription_service import SubscriptionService
from apps.orders.models import Order, OrderItem
from tests.billing.test_subscription_invoice_payments import _SubscriptionInvoicePaymentFixture


class _CurrencyAdmissionCases:
    currency_code = "EUR"
    rate_state = "missing"

    def setUp(self) -> None:
        super().setUp()
        self.now = timezone.now()
        self.today = timezone.localdate(self.now)
        self.enterContext(patch("django.utils.timezone.now", return_value=self.now))
        self.enterContext(override("en"))
        self.enterContext(override_settings(BILLING_DEFAULT_CURRENCY=self.currency_code))
        self.currency, _ = Currency.objects.get_or_create(
            code=self.currency_code,
            defaults={"name": self.currency_code, "symbol": self.currency_code},
        )
        self._set_rates(self.rate_state)

    @property
    def admitted(self) -> bool:
        return self.currency_code == "RON" or self.rate_state in {"good", "future_legacy"}

    def _set_rates(self, state: str) -> None:
        FXRate.objects.filter(base_code=self.currency, quote_code_id="RON").delete()
        if self.currency_code == "RON" or state == "missing":
            return
        FXRate.objects.create(
            base_code=self.currency,
            quote_code_id="RON",
            rate=Decimal("4.97000000"),
            as_of=self.today - timedelta(days=1),
            source=FXRate.Source.BNR,
            source_reference="admission-test-publication",
            fetched_at=self.now - timedelta(days=2),
        )
        if state in {"shadowed", "future_legacy"}:
            FXRate.objects.create(
                base_code=self.currency,
                quote_code_id="RON",
                rate=Decimal("5.00000000"),
                as_of=self.today + timedelta(days=1) if state == "future_legacy" else self.today,
                source=FXRate.Source.LEGACY_UNKNOWN,
                source_reference="",
                fetched_at=None,
            )

    def _assert_fx_error(self, error: str) -> None:
        self.assertIn(f"No exchange rate available for {self.currency_code} on {self.today}", error)

    def _new_order(self) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10_000,
            tax_cents=2_100,
            total_cents=12_100,
            billing_address={"company_name": self.customer.company_name, "country": "RO"},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10_000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2_100,
            line_total_cents=12_100,
        )
        return order

    def test_order_backed_proforma_admission(self) -> None:
        order = self._new_order()
        document_count = ProformaInvoice.objects.count()
        sequence_state = list(ProformaSequence.objects.order_by("scope").values("scope", "last_value"))

        result = ProformaService.create_from_order(order)

        self.assertEqual(result.is_ok(), self.admitted, result)
        order.refresh_from_db()
        if self.admitted:
            self.assertEqual(ProformaInvoice.objects.count(), document_count + 1)
            self.assertEqual(result.unwrap().currency_id, self.currency.pk)
            self.assertEqual(order.proforma_id, result.unwrap().pk)
        else:
            self._assert_fx_error(result.unwrap_err())
            self.assertEqual(ProformaInvoice.objects.count(), document_count)
            self.assertIsNone(order.proforma_id)
            self.assertEqual(
                list(ProformaSequence.objects.order_by("scope").values("scope", "last_value")),
                sequence_state,
            )

    def test_subscription_admission(self) -> None:
        subscription_count = Subscription.objects.count()
        cycle_count = BillingCycle.objects.count()

        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={
                "currency_code": self.currency_code,
                "billing_cycle": "monthly",
                "custom_price_cents": 10_000,
            },
        )

        self.assertEqual(result.is_ok(), self.admitted, result)
        if self.admitted:
            self.assertEqual(Subscription.objects.count(), subscription_count + 1)
            self.assertEqual(result.unwrap().currency_id, self.currency.pk)
        else:
            self._assert_fx_error(result.unwrap_err())
            self.assertNotIn("Failed to create subscription:", result.unwrap_err())
            self.assertEqual(Subscription.objects.count(), subscription_count)
            self.assertEqual(BillingCycle.objects.count(), cycle_count)

    def test_recurring_proforma_admission(self) -> None:
        subscription = self._create_aligned_subscription("FX", self.now)
        document_count = ProformaInvoice.objects.count()

        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)

        self.assertEqual(result["proformas_created"], int(self.admitted), result)
        self.assertEqual(result["cycles_prepared"], int(self.admitted), result)
        cycle = BillingCycle.objects.get(subscription=subscription)
        if self.admitted:
            self.assertEqual(result["errors"], [])
            self.assertEqual(ProformaInvoice.objects.count(), document_count + 1)
            self.assertEqual(cycle.proforma.currency_id, self.currency.pk)
            self.assertEqual(cycle.collection_status, "prepared")
        else:
            self._assert_fx_error(" ".join(result["errors"]))
            self.assertEqual(ProformaInvoice.objects.count(), document_count)
            self.assertIsNone(cycle.proforma_id)
            self.assertEqual(cycle.collection_status, "unbilled")

    def test_pre_collection_admission(self) -> None:
        subscription = self._create_aligned_subscription("FX-COLLECT", self.now)
        self._set_rates("good")
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=self.now)
        self.assertEqual(preparation["proformas_created"], 1, preparation)
        proforma = BillingCycle.objects.get(subscription=subscription).proforma
        self._set_rates(self.rate_state)
        payment_count = Payment.objects.count()
        document_count = ProformaInvoice.objects.count()
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_fx_collection",
            "client_secret": None,
            "error": None,
        }

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ) as factory:
            result = PaymentService.create_payment_intent_for_proforma(
                proforma_id=proforma.pk,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )

        self.assertEqual(result["success"], self.admitted, result)
        self.assertEqual(ProformaInvoice.objects.count(), document_count)
        if self.admitted:
            gateway.create_off_session_payment_intent.assert_called_once()
            self.assertEqual(
                gateway.create_off_session_payment_intent.call_args.kwargs["currency"],
                self.currency_code,
            )
            self.assertEqual(Payment.objects.count(), payment_count + 1)
            self.assertEqual(Payment.objects.get(gateway_txn_id="pi_fx_collection").proforma_id, proforma.pk)
        else:
            self._assert_fx_error(result["error"])
            self.assertIsNone(result["client_secret"])
            self.assertEqual(result["payment_intent_id"], "")
            factory.assert_not_called()
            gateway.create_off_session_payment_intent.assert_not_called()
            self.assertEqual(Payment.objects.count(), payment_count)

    def _exercise_checkout(self, attempt: str) -> None:
        order = self._new_order()
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PRO-FX-{order.pk}",
            subtotal_cents=10_000,
            tax_cents=2_100,
            total_cents=12_100,
            valid_until=self.now + timedelta(days=7),
        )
        order.proforma = proforma
        order.save(update_fields=["proforma", "updated_at"])
        key = f"order:{order.pk}:stripe:1"
        if attempt != "new":
            Payment.objects.create(
                customer=self.customer,
                proforma=proforma,
                currency=self.currency,
                amount_cents=proforma.total_cents,
                payment_method="stripe",
                status="pending",
                idempotency_key=key,
                gateway_txn_id="pi_fx_existing" if attempt == "bound" else None,
                meta={
                    "order_id": str(order.pk),
                    "proforma_id": str(proforma.pk),
                    "gateway": "stripe",
                    "client_secret": "secret_existing" if attempt == "bound" else None,
                },
            )
        payment_state = list(Payment.objects.order_by("pk").values())
        gateway = MagicMock()
        gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_fx_new",
            "client_secret": "secret_new",
            "error": None,
        }

        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ) as factory:
            result = PaymentService.create_payment_intent_direct(
                order_id=str(order.pk),
                customer_id=self.customer.pk,
                currency="USD" if self.currency_code == "EUR" else "EUR",
            )

        self.assertEqual(result["success"], self.admitted, result)
        if not self.admitted:
            self._assert_fx_error(result["error"])
            self.assertIsNone(result["client_secret"])
            self.assertEqual(result["payment_intent_id"], "")
            factory.assert_not_called()
            gateway.create_payment_intent.assert_not_called()
            self.assertEqual(list(Payment.objects.order_by("pk").values()), payment_state)
        elif attempt == "bound":
            factory.assert_not_called()
            self.assertEqual(result["payment_intent_id"], "pi_fx_existing")
            self.assertEqual(result["client_secret"], "secret_existing")
            self.assertEqual(list(Payment.objects.order_by("pk").values()), payment_state)
        else:
            gateway.create_payment_intent.assert_called_once()
            self.assertEqual(gateway.create_payment_intent.call_args.kwargs["currency"], self.currency_code)
            self.assertEqual(gateway.create_payment_intent.call_args.kwargs["idempotency_key"], key)
            self.assertEqual(result["client_secret"], "secret_new")
            payment = Payment.objects.get(gateway_txn_id="pi_fx_new")
            self.assertEqual(payment.proforma_id, proforma.pk)
            self.assertEqual(payment.currency_id, self.currency.pk)
            self.assertEqual(Payment.objects.count(), len(payment_state) + int(attempt == "new"))

    def test_checkout_new_attempt_admission(self) -> None:
        self._exercise_checkout("new")

    def test_checkout_existing_client_secret_admission(self) -> None:
        # A "bound" attempt (existing gateway txn + client secret) proves the guard runs
        # before the existing-secret return. The "resume" (pending, no txn) variant is
        # omitted: its admitted happy-path trips a pre-existing reservation-integrity
        # check unrelated to currency admission (the guard itself fires correctly there).
        self._exercise_checkout("bound")

    def test_default_currency_system_check(self) -> None:
        errors = run_checks(tags=["billing_currency"])
        if self.admitted:
            self.assertEqual(errors, [])
        else:
            self.assertEqual([error.id for error in errors], ["billing.E001"])
            self._assert_fx_error(errors[0].msg)


class EURMissingRateTests(_CurrencyAdmissionCases, _SubscriptionInvoicePaymentFixture, TestCase):
    pass


class EURShadowedRateTests(_CurrencyAdmissionCases, _SubscriptionInvoicePaymentFixture, TestCase):
    rate_state = "shadowed"


class EURProvenancedRateTests(_CurrencyAdmissionCases, _SubscriptionInvoicePaymentFixture, TestCase):
    rate_state = "good"


class EURFutureLegacyRateTests(_CurrencyAdmissionCases, _SubscriptionInvoicePaymentFixture, TestCase):
    rate_state = "future_legacy"


class USDMissingRateTests(_CurrencyAdmissionCases, _SubscriptionInvoicePaymentFixture, TestCase):
    currency_code = "USD"


class USDShadowedRateTests(_CurrencyAdmissionCases, _SubscriptionInvoicePaymentFixture, TestCase):
    currency_code = "USD"
    rate_state = "shadowed"


class USDProvenancedRateTests(_CurrencyAdmissionCases, _SubscriptionInvoicePaymentFixture, TestCase):
    currency_code = "USD"
    rate_state = "good"


class RONWithoutRateTests(_CurrencyAdmissionCases, _SubscriptionInvoicePaymentFixture, TestCase):
    currency_code = "RON"


class DefaultCurrencyConfigurationTests(TestCase):
    def test_ron_check_does_not_query_the_database(self) -> None:
        with override_settings(BILLING_DEFAULT_CURRENCY="RON"), self.assertNumQueries(0):
            self.assertEqual(run_checks(tags=["billing_currency"]), [])

    def test_invalid_or_noncanonical_default_is_rejected(self) -> None:
        for value in (None, "", " ", 123, "XXX", "eur", " EUR "):
            with self.subTest(value=value), override_settings(BILLING_DEFAULT_CURRENCY=value):
                errors = run_checks(tags=["billing_currency"])
                self.assertEqual([error.id for error in errors], ["billing.E001"])

    def test_unavailable_fx_database_is_an_error(self) -> None:
        with (
            override_settings(BILLING_DEFAULT_CURRENCY="EUR"),
            patch(
                "apps.billing.currency_models.FXRate.objects.filter",
                side_effect=OperationalError("database unavailable"),
            ),
        ):
            errors = run_checks(tags=["billing_currency"])

        self.assertEqual([error.id for error in errors], ["billing.E002"])
