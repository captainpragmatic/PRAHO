"""PostgreSQL concurrency regressions for recurring charge revocation (#316)."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase
from rest_framework.test import APIRequestFactory

from apps.api.services.views import update_service_auto_renew_api
from apps.billing.gateways.base import PaymentIntentResult
from apps.billing.payment_models import Payment
from apps.billing.payment_service import PaymentService
from apps.billing.recurring_authorization_service import RecurringPaymentAuthorizationService
from apps.billing.recurring_locking import lock_recurring_collection_customer
from apps.billing.recurring_models import RecurringPaymentAuthorization
from apps.billing.subscription_models import Subscription
from apps.billing.subscription_service import SubscriptionService
from apps.provisioning.models import Service
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.billing.test_subscription_invoice_payments import _intent_result, _SubscriptionInvoicePaymentFixture


class RecurringCollectionPostgresConcurrencyTests(_SubscriptionInvoicePaymentFixture, TransactionTestCase):
    """Prove revocation and charge submission have one PostgreSQL ordering boundary."""

    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("Recurring collection concurrency requires PostgreSQL row locks")
        super().setUp()
        self.owner = User.objects.create_user(email=f"owner-{uuid.uuid4().hex[:8]}@example.test")
        CustomerMembership.objects.create(
            customer=self.customer,
            user=self.owner,
            role="owner",
            is_primary=True,
        )

    @staticmethod
    def _in_separate_connection(operation: Callable[[], Any]) -> Any:
        close_old_connections()
        try:
            return operation()
        finally:
            connection.close()

    def _charge_invoice(
        self,
        gateway_called: threading.Event,
        gateway_initialization_started: threading.Event | None = None,
        reservation_started: threading.Event | None = None,
    ) -> PaymentIntentResult:
        gateway = MagicMock()

        def submit_charge(**_kwargs: object) -> PaymentIntentResult:
            gateway_called.set()
            return _intent_result(payment_intent_id=f"pi_race_{uuid.uuid4().hex[:8]}")

        gateway.create_off_session_payment_intent.side_effect = submit_charge

        def create_gateway(_gateway_name: str) -> MagicMock:
            if gateway_initialization_started is not None:
                gateway_initialization_started.set()
            return gateway

        original_payment_save = Payment.save

        def track_reservation(payment: Payment, *args: object, **kwargs: object) -> None:
            if (
                reservation_started is not None
                and payment.pk is None
                and payment.invoice_id == self.invoice.id
                and payment.meta.get("source") == "recurring_billing"
            ):
                reservation_started.set()
            original_payment_save(payment, *args, **kwargs)

        with (
            patch.object(Payment, "save", new=track_reservation),
            patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway", side_effect=create_gateway),
        ):
            return PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )


    def test_customer_boundary_allows_manual_payment_foreign_key_insert(self) -> None:
        boundary_locked = threading.Event()
        release_boundary = threading.Event()

        def hold_customer_boundary() -> None:
            with transaction.atomic():
                lock_recurring_collection_customer(self.customer.id)
                boundary_locked.set()
                if not release_boundary.wait(timeout=10):
                    raise AssertionError("Timed out releasing recurring-collection customer boundary")

        def create_manual_payment() -> Payment:
            return Payment.objects.create(
                customer_id=self.customer.id,
                invoice_id=self.invoice.id,
                amount_cents=1,
                currency_id=self.currency.code,
                payment_method="bank",
                status="pending",
                idempotency_key=f"manual-fk-{uuid.uuid4().hex}",
                meta={"source": "manual_lock_regression"},
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            boundary_future = executor.submit(self._in_separate_connection, hold_customer_boundary)
            self.assertTrue(boundary_locked.wait(timeout=5), "Customer boundary was not acquired")
            payment_future = executor.submit(self._in_separate_connection, create_manual_payment)
            try:
                payment = payment_future.result(timeout=2)
            finally:
                release_boundary.set()
            boundary_future.result(timeout=10)

        self.assertEqual(payment.customer_id, self.customer.id)
        self.assertEqual(payment.invoice_id, self.invoice.id)

    def test_withdrawal_started_first_prevents_gateway_submission(self) -> None:
        withdrawal_locked = threading.Event()
        release_withdrawal = threading.Event()
        reservation_started = threading.Event()
        gateway_called = threading.Event()
        original_withdraw = RecurringPaymentAuthorization.withdraw

        def pause_withdrawal(
            authorization: RecurringPaymentAuthorization,
            *,
            actor: User,
            reason: str,
            at: datetime | None = None,
        ) -> None:
            withdrawal_locked.set()
            if not release_withdrawal.wait(timeout=10):
                raise AssertionError("Timed out releasing authorization withdrawal")
            original_withdraw(authorization, actor=actor, reason=reason, at=at)

        def withdraw() -> Any:
            return RecurringPaymentAuthorizationService.withdraw(
                authorization=RecurringPaymentAuthorization.objects.get(pk=self.authorization.pk),
                actor=User.objects.get(pk=self.owner.pk),
                reason="Customer withdrew before collection",
            )

        def charge() -> PaymentIntentResult:
            return self._charge_invoice(gateway_called, reservation_started=reservation_started)

        with (
            patch.object(RecurringPaymentAuthorization, "withdraw", new=pause_withdrawal),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            withdrawal_future = executor.submit(self._in_separate_connection, withdraw)
            self.assertTrue(withdrawal_locked.wait(timeout=5), "Withdrawal never acquired its database locks")
            charge_future = executor.submit(self._in_separate_connection, charge)
            self.assertTrue(reservation_started.wait(timeout=5), "Charge never created its local reservation")
            try:
                self.assertFalse(
                    gateway_called.wait(timeout=2),
                    "Gateway submission escaped while authorization withdrawal held the boundary",
                )
            finally:
                release_withdrawal.set()
            withdrawal_result = withdrawal_future.result(timeout=10)
            charge_result = charge_future.result(timeout=10)

        self.assertTrue(withdrawal_result.is_ok(), withdrawal_result)
        self.assertFalse(charge_result["success"], charge_result)
        self.assertIn("authorization", (charge_result.get("error") or "").lower())
        self.assertFalse(gateway_called.is_set())

    def test_cancellation_started_first_prevents_gateway_submission(self) -> None:
        cancellation_locked = threading.Event()
        release_cancellation = threading.Event()
        reservation_started = threading.Event()
        gateway_called = threading.Event()
        original_cancel = Subscription.cancel

        def pause_cancellation(subscription: Subscription, *args: object, **kwargs: object) -> None:
            cancellation_locked.set()
            if not release_cancellation.wait(timeout=10):
                raise AssertionError("Timed out releasing subscription cancellation")
            original_cancel(subscription, *args, **kwargs)

        def cancel() -> Any:
            return SubscriptionService.cancel_subscription(
                Subscription.objects.get(pk=self.subscription.pk),
                reason="Customer cancelled before collection",
                at_period_end=True,
                user=User.objects.get(pk=self.owner.pk),
            )

        def charge() -> PaymentIntentResult:
            return self._charge_invoice(gateway_called, reservation_started=reservation_started)

        with (
            patch.object(Subscription, "cancel", new=pause_cancellation),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            cancellation_future = executor.submit(self._in_separate_connection, cancel)
            self.assertTrue(cancellation_locked.wait(timeout=5), "Cancellation never acquired its database locks")
            charge_future = executor.submit(self._in_separate_connection, charge)
            self.assertTrue(reservation_started.wait(timeout=5), "Charge never created its local reservation")
            try:
                self.assertFalse(
                    gateway_called.wait(timeout=2),
                    "Gateway submission escaped while cancellation held the boundary",
                )
            finally:
                release_cancellation.set()
            cancellation_result = cancellation_future.result(timeout=10)
            charge_result = charge_future.result(timeout=10)

        self.assertTrue(cancellation_result.is_ok(), cancellation_result)
        self.assertFalse(charge_result["success"], charge_result)
        self.assertIn("scheduled for cancellation", (charge_result.get("error") or "").lower())
        self.assertFalse(gateway_called.is_set())

    def test_global_disable_started_first_prevents_gateway_submission(self) -> None:
        setting_locked = threading.Event()
        release_setting = threading.Event()
        gateway_initialization_started = threading.Event()
        gateway_called = threading.Event()
        original_save = SystemSetting.save

        def pause_setting_save(setting: SystemSetting, *args: object, **kwargs: object) -> None:
            if setting.key == "billing.recurring_auto_collection_enabled" and setting.value is False:
                setting_locked.set()
                if not release_setting.wait(timeout=10):
                    raise AssertionError("Timed out releasing recurring-collection kill switch")
            original_save(setting, *args, **kwargs)

        def disable_collection() -> None:
            SettingsService.set_setting("billing.recurring_auto_collection_enabled", False)

        def charge() -> PaymentIntentResult:
            return self._charge_invoice(
                gateway_called,
                gateway_initialization_started=gateway_initialization_started,
            )

        with (
            patch.object(SystemSetting, "save", new=pause_setting_save),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            setting_future = executor.submit(self._in_separate_connection, disable_collection)
            self.assertTrue(setting_locked.wait(timeout=5), "Kill switch update never acquired its database lock")
            charge_future = executor.submit(self._in_separate_connection, charge)
            self.assertTrue(
                gateway_initialization_started.wait(timeout=5), "Charge never started gateway initialization"
            )
            try:
                self.assertFalse(
                    gateway_called.wait(timeout=2),
                    "Gateway submission escaped while the kill-switch update held the boundary",
                )
            finally:
                release_setting.set()
            setting_future.result(timeout=10)
            charge_result = charge_future.result(timeout=10)

        self.assertIs(
            SystemSetting.objects.get(key="billing.recurring_auto_collection_enabled").get_typed_value(), False
        )
        self.assertFalse(charge_result["success"], charge_result)
        self.assertIn("disabled", (charge_result.get("error") or "").lower())
        self.assertFalse(gateway_called.is_set())

    def test_service_renewal_opt_out_started_first_prevents_gateway_submission(self) -> None:
        service_locked = threading.Event()
        release_service = threading.Event()
        reservation_started = threading.Event()
        gateway_called = threading.Event()
        original_save = Service.save

        def pause_service_save(service: Service, *args: object, **kwargs: object) -> None:
            if service.pk == self.service.pk and service.auto_renew is False:
                service_locked.set()
                if not release_service.wait(timeout=10):
                    raise AssertionError("Timed out releasing service renewal opt-out")
            original_save(service, *args, **kwargs)

        def disable_service_renewal() -> Any:
            request = APIRequestFactory().post(
                f"/api/services/{self.service.id}/auto-renew/",
                {"auto_renew": False},
                format="json",
            )
            customer = self.customer.__class__.objects.get(pk=self.customer.pk)
            with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(customer, None)):
                return update_service_auto_renew_api(request, service_id=self.service.id)

        def charge() -> PaymentIntentResult:
            return self._charge_invoice(gateway_called, reservation_started=reservation_started)

        with (
            patch.object(Service, "save", new=pause_service_save),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            opt_out_future = executor.submit(self._in_separate_connection, disable_service_renewal)
            self.assertTrue(service_locked.wait(timeout=5), "Renewal opt-out never acquired its database locks")
            charge_future = executor.submit(self._in_separate_connection, charge)
            self.assertTrue(reservation_started.wait(timeout=5), "Charge never created its local reservation")
            try:
                self.assertFalse(
                    gateway_called.wait(timeout=2),
                    "Gateway submission escaped while renewal opt-out held the boundary",
                )
            finally:
                release_service.set()
            opt_out_response = opt_out_future.result(timeout=10)
            charge_result = charge_future.result(timeout=10)

        self.assertEqual(opt_out_response.status_code, 200)
        self.assertFalse(charge_result["success"], charge_result)
        self.assertIn("renewal disabled", (charge_result.get("error") or "").lower())
        self.assertFalse(gateway_called.is_set())

    def test_gateway_submission_started_first_defers_withdrawal(self) -> None:
        revalidation_complete = threading.Event()
        release_charge = threading.Event()
        withdrawal_started = threading.Event()
        gateway_called = threading.Event()

        from apps.billing import payment_service as payment_service_module  # noqa: PLC0415

        original_revalidate = payment_service_module._revalidate_invoice_payment_reservation

        def pause_after_revalidation(**kwargs: object) -> str | None:
            result = original_revalidate(**kwargs)
            revalidation_complete.set()
            if not release_charge.wait(timeout=10):
                raise AssertionError("Timed out releasing in-flight gateway submission")
            return result

        def charge() -> PaymentIntentResult:
            return self._charge_invoice(gateway_called)

        def withdraw() -> Any:
            withdrawal_started.set()
            return RecurringPaymentAuthorizationService.withdraw(
                authorization=RecurringPaymentAuthorization.objects.get(pk=self.authorization.pk),
                actor=User.objects.get(pk=self.owner.pk),
                reason="Customer withdrew during in-flight collection",
            )

        with patch.object(
            payment_service_module,
            "_revalidate_invoice_payment_reservation",
            new=pause_after_revalidation,
        ), ThreadPoolExecutor(max_workers=2) as executor:
            charge_future = executor.submit(self._in_separate_connection, charge)
            self.assertTrue(revalidation_complete.wait(timeout=5), "Charge never reached final revalidation")
            withdrawal_future = executor.submit(self._in_separate_connection, withdraw)
            self.assertTrue(withdrawal_started.wait(timeout=5), "Withdrawal worker did not start")
            try:
                with self.assertRaises(FutureTimeoutError):
                    withdrawal_future.result(timeout=2)
            finally:
                release_charge.set()
            charge_result = charge_future.result(timeout=10)
            withdrawal_result = withdrawal_future.result(timeout=10)

        self.assertTrue(charge_result["success"], charge_result)
        self.assertTrue(gateway_called.is_set())
        self.assertTrue(withdrawal_result.is_ok(), withdrawal_result)
        self.authorization.refresh_from_db()
        self.assertEqual(self.authorization.status, "withdrawn")

    def test_kill_switch_row_is_not_locked_across_the_gateway_call(self) -> None:
        """W1: the global kill-switch row must be released before the gateway
        round-trip. While a charge is mid-Stripe-call (its boundary held), a
        second connection must still be able to lock the setting row — otherwise
        one hung gateway call serializes every customer's charge and blocks the
        kill switch itself."""
        gateway_called = threading.Event()
        release_charge = threading.Event()

        def charge_holding_boundary() -> PaymentIntentResult:
            gateway = MagicMock()

            def submit_charge(**_kwargs: object) -> PaymentIntentResult:
                gateway_called.set()
                if not release_charge.wait(timeout=10):
                    raise AssertionError("Timed out releasing held charge")
                return _intent_result(payment_intent_id=f"pi_hold_{uuid.uuid4().hex[:8]}")

            gateway.create_off_session_payment_intent.side_effect = submit_charge
            with patch(
                "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
                return_value=gateway,
            ):
                return PaymentService.create_payment_intent_for_invoice(
                    invoice_id=self.invoice.id,
                    payment_method_id=self.payment_method.stripe_payment_method_id,
                )

        with ThreadPoolExecutor(max_workers=1) as executor:
            charge_future = executor.submit(self._in_separate_connection, charge_holding_boundary)
            self.assertTrue(gateway_called.wait(timeout=5), "Charge never reached the gateway call")
            try:
                # nowait raises immediately if the row is still locked by the
                # in-flight charge's boundary — pre-fix (FOR UPDATE held across
                # the gateway call) this fails; post-fix it succeeds.
                with transaction.atomic():
                    SystemSetting.objects.select_for_update(nowait=True).get(
                        key="billing.recurring_auto_collection_enabled"
                    )
            finally:
                release_charge.set()
            charge_result = charge_future.result(timeout=10)

        self.assertTrue(charge_result["success"], charge_result)
