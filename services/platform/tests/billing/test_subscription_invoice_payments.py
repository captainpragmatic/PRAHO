"""Regression tests for invoice-native recurring subscription payments (#301)."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.billing.gateways.base import PaymentConfirmResult, PaymentIntentResult
from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.invoice_models import Invoice, InvoiceLine
from apps.billing.metering_models import BillingCycle, UsageAggregation, UsageMeter
from apps.billing.payment_convergence import PaymentSuccessService
from apps.billing.payment_models import Payment, PaymentRetryAttempt, PaymentRetryPolicy
from apps.billing.payment_service import (
    PaymentService,
    _revalidate_invoice_payment_reservation,
    _submit_recurring_charge_under_revocation_lock,
)
from apps.billing.proforma_models import ProformaInvoice, ProformaLine
from apps.billing.recurring_authorization_service import RecurringPaymentAuthorizationService
from apps.billing.recurring_billing import (
    RecurringBillingOrchestrator,
    RecurringCollectionGate,
    next_billing_period_end,
)
from apps.billing.recurring_models import RecurringPaymentAuthorization
from apps.billing.subscription_models import Subscription
from apps.billing.subscription_service import SubscriptionLifecycleService
from apps.billing.tasks import process_auto_payment, run_payment_collection
from apps.customers.models import Customer, CustomerAddress, CustomerPaymentMethod
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.settings.services import SettingsService


def _intent_result(
    *,
    payment_intent_id: str = "pi_invoice_301",
    success: bool = True,
    error: str | None = None,
) -> PaymentIntentResult:
    return PaymentIntentResult(
        success=success,
        payment_intent_id=payment_intent_id,
        client_secret=None,
        error=error,
    )


class _SubscriptionInvoicePaymentFixture:
    """Shared invoice-native recurring-billing fixture."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={
                "name": "Romanian Leu",
                "symbol": "lei",
                "decimals": 2,
            },
        )
        self.customer = Customer.objects.create(
            name="Recurring Customer SRL",
            customer_type="company",
            company_name="Recurring Customer SRL",
            primary_email="recurring@example.ro",
            status="active",
        )
        self.payment_method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="stripe_card",
            stripe_customer_id="cus_recurring_301",
            stripe_payment_method_id="pm_recurring_301",
            display_name="Visa ending 4242",
            last_four="4242",
            is_default=True,
            is_active=True,
        )
        self.authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=self.payment_method,
            status="active",
            setup_intent_id="seti_recurring_301",
            terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            terms_text=RecurringPaymentAuthorizationService.TERMS_TEXT,
            terms_text_hash=hashlib.sha256(RecurringPaymentAuthorizationService.TERMS_TEXT.encode("utf-8")).hexdigest(),
            granted_by_role="owner",
            granted_at=timezone.now(),
        )
        self.product = Product.objects.create(
            slug=f"recurring-plan-{uuid.uuid4().hex[:8]}",
            name="Recurring Plan",
            product_type="hosting",
        )
        now = timezone.now()
        self.service_plan = ServicePlan.objects.create(
            name="Recurring Hosting Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("100.00"),
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            service_name="Recurring Hosting",
            username=f"recurring{uuid.uuid4().hex[:8]}",
            billing_cycle="monthly",
            price=Decimal("100.00"),
            status="active",
            activated_at=now - timedelta(days=30),
            expires_at=now,
        )
        next_period_end = next_billing_period_end(now, "monthly", anchor_day=now.day)
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            service=self.service,
            currency=self.currency,
            subscription_number=f"SUB-{uuid.uuid4().hex[:8].upper()}",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=10_000,
            quantity=1,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            next_billing_date=now,
            billing_anchor_day=now.day,
            saved_payment_method=self.payment_method,
            payment_authorization=self.authorization,
            auto_payment_enabled=True,
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number=f"INV-{uuid.uuid4().hex[:8].upper()}",
            currency=self.currency,
            subtotal_cents=10_000,
            tax_cents=2_100,
            total_cents=12_100,
            due_at=timezone.now() + timedelta(days=14),
            bill_to_name=self.customer.company_name,
            bill_to_email=self.customer.primary_email,
            bill_to_country="RO",
            meta={"type": "recurring"},
        )
        self.invoice.issue()
        self.invoice.save()
        self.billing_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=self.subscription.current_period_end,
            period_end=next_period_end,
            status="upcoming",
            collection_status="scheduled",
            invoice=self.invoice,
            base_charge_cents=10_000,
            tax_cents=2_100,
            total_cents=12_100,
            charge_scheduled_at=now,
        )
        SettingsService.update_setting(
            key="billing.recurring_auto_collection_enabled",
            value=True,
            reason="Recurring payment test setup",
        )

    def _succeeded_gateway_result(self) -> PaymentConfirmResult:
        return PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=self.invoice.total_cents,
            currency=self.currency.code.lower(),
            customer_id=self.payment_method.stripe_customer_id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
            metadata={
                "invoice_id": str(self.invoice.id),
                "invoice_number": self.invoice.number,
                "customer_id": str(self.customer.id),
                "platform": "PRAHO",
                "source": "recurring_billing",
                "payment_attempt": "1",
            },
        )

    def _create_pending_invoice_payment(self, payment_intent_id: str) -> Payment:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(payment_intent_id=payment_intent_id)
        with patch(
            "apps.billing.payment_service.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )
        self.assertTrue(result["success"], result)
        return Payment.objects.get(gateway_txn_id=payment_intent_id)

    def _create_aligned_subscription(self, suffix: str, now: datetime) -> Subscription:
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            service_name=f"Recurring Hosting {suffix}",
            username=f"recurring{suffix}{uuid.uuid4().hex[:6]}",
            billing_cycle="monthly",
            price=Decimal("100.00"),
            status="active",
            activated_at=now - timedelta(days=30),
            expires_at=self.subscription.current_period_end,
        )
        return Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            service=service,
            currency=self.currency,
            subscription_number=f"SUB-{suffix}-{uuid.uuid4().hex[:6].upper()}",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=10_000,
            quantity=1,
            current_period_start=self.subscription.current_period_start,
            current_period_end=self.subscription.current_period_end,
            next_billing_date=now,
            billing_anchor_day=self.subscription.billing_anchor_day,
            next_proforma_at=now - timedelta(minutes=1),
            next_charge_at=now + timedelta(days=7),
            saved_payment_method=self.payment_method,
            payment_authorization=self.authorization,
            auto_payment_enabled=True,
        )


class SubscriptionInvoicePaymentTestCase(_SubscriptionInvoicePaymentFixture, TestCase):
    """Exercise the real invoice, Payment, and recurring-billing path."""

    def _corrupt_unrelated_bank_details(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE customer_payment_methods SET bank_details = %s WHERE id = %s",
                [json.dumps("aes:v2:!!!garbage!!!"), self.payment_method.pk],
            )

    def test_collection_gate_does_not_read_unrelated_bank_details(self) -> None:
        self._corrupt_unrelated_bank_details()

        result = RecurringCollectionGate.authorize_invoice(
            self.invoice,
            self.payment_method,
        )

        self.assertTrue(result.is_ok(), result)

    def test_proforma_preparation_does_not_read_unrelated_bank_details(self) -> None:
        now = timezone.now()
        self._create_aligned_subscription("CORRUPT-BANK", now)
        self._corrupt_unrelated_bank_details()

        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(result["proformas_created"], 1)
        self.assertEqual(result["errors"], [])

    def test_due_aligned_services_share_one_cycle_linked_proforma_idempotently(self) -> None:
        now = timezone.now()
        first_subscription = self._create_aligned_subscription("ONE", now)
        second_subscription = self._create_aligned_subscription("TWO", now)

        first_result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        second_result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(first_result["proformas_created"], 1)
        self.assertEqual(first_result["cycles_prepared"], 2)
        self.assertEqual(second_result["proformas_created"], 0)
        self.assertEqual(ProformaInvoice.objects.count(), 1)
        proforma = ProformaInvoice.objects.get()
        self.assertEqual(proforma.status, "sent")
        self.assertEqual(proforma.subtotal_cents, 20_000)
        self.assertEqual(proforma.tax_cents, 4_200)
        self.assertEqual(proforma.total_cents, 24_200)
        self.assertEqual(proforma.lines.count(), 2)
        cycles = list(BillingCycle.objects.order_by("subscription_id"))
        self.assertEqual(
            {cycle.subscription_id for cycle in cycles},
            {self.subscription.id, first_subscription.id, second_subscription.id},
        )
        renewal_cycles = [cycle for cycle in cycles if cycle.subscription_id != self.subscription.id]
        self.assertTrue(all(cycle.proforma_id == proforma.id for cycle in renewal_cycles))
        self.assertTrue(all(cycle.collection_status == "prepared" for cycle in renewal_cycles))
        self.assertTrue(all(cycle.invoice_id is None for cycle in renewal_cycles))
        self.assertEqual(
            {line.billing_cycle_id for line in proforma.lines.all()},
            {cycle.id for cycle in renewal_cycles},
        )
        self.assertEqual(
            {line.service_id for line in proforma.lines.all()},
            {first_subscription.service_id, second_subscription.service_id},
        )
        first_subscription.refresh_from_db()
        self.assertNotEqual(first_subscription.current_period_end, renewal_cycles[0].period_end)

    def test_lead_time_change_does_not_reschedule_an_already_prepared_cycle(self) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("LEAD-PREPARED", now)

        first_result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        subscription.refresh_from_db()
        prepared_at = subscription.next_proforma_at
        setting_result = SettingsService.update_setting(
            key="billing.invoice_generation_lead_days",
            value=7,
            reason="prepared schedule stability test",
        )
        self.assertTrue(setting_result.is_ok(), setting_result)

        second_result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(first_result["proformas_created"], 1)
        self.assertEqual(second_result["proformas_created"], 0)
        subscription.refresh_from_db()
        self.assertEqual(subscription.next_proforma_at, prepared_at)
        self.assertEqual(ProformaInvoice.objects.count(), 1)

    def test_increased_invoice_lead_reschedules_an_existing_cycle_earlier(self) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("LEAD-EARLIER", now)
        period_end = now + timedelta(days=20)
        subscription.current_period_end = period_end
        subscription.next_proforma_at = period_end - timedelta(days=14)
        subscription.next_billing_date = subscription.next_proforma_at
        subscription.next_charge_at = period_end - timedelta(days=7)
        subscription.save(
            update_fields=[
                "current_period_end",
                "next_proforma_at",
                "next_billing_date",
                "next_charge_at",
                "updated_at",
            ]
        )
        setting_result = SettingsService.update_setting(
            key="billing.invoice_generation_lead_days",
            value=21,
            reason="reschedule test",
        )
        self.assertTrue(setting_result.is_ok(), setting_result)

        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(result["proformas_created"], 1)
        subscription.refresh_from_db()
        self.assertEqual(subscription.next_proforma_at, period_end - timedelta(days=21))

    def test_reduced_invoice_lead_postpones_an_unprepared_existing_cycle(self) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("LEAD-LATER", now)
        period_end = now + timedelta(days=10)
        subscription.current_period_end = period_end
        subscription.next_proforma_at = period_end - timedelta(days=14)
        subscription.next_billing_date = subscription.next_proforma_at
        subscription.next_charge_at = period_end - timedelta(days=7)
        subscription.save(
            update_fields=[
                "current_period_end",
                "next_proforma_at",
                "next_billing_date",
                "next_charge_at",
                "updated_at",
            ]
        )
        setting_result = SettingsService.update_setting(
            key="billing.invoice_generation_lead_days",
            value=7,
            reason="reschedule test",
        )
        self.assertTrue(setting_result.is_ok(), setting_result)

        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(result["proformas_created"], 0)
        subscription.refresh_from_db()
        self.assertEqual(subscription.next_proforma_at, period_end - timedelta(days=7))

    def test_recurring_proforma_snapshots_individual_cnp(self) -> None:
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        self.customer.customer_type = "individual"
        self.customer.company_name = ""
        self.customer.save(update_fields=["customer_type", "company_name"])
        CustomerTaxProfile.objects.create(customer=self.customer, cnp="1850101123451")
        now = timezone.now()
        subscription = self._create_aligned_subscription("B2C", now)

        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(result["proformas_created"], 1)
        cycle = BillingCycle.objects.get(subscription=subscription)
        self.assertEqual(cycle.proforma.bill_to_cnp, "1850101123451")
        self.assertEqual(cycle.proforma.bill_to_tax_id, "")

    def test_recurring_proforma_normalizes_romanian_address_country(self) -> None:
        CustomerAddress.objects.create(
            customer=self.customer,
            is_billing=True,
            address_line1="Strada Test 1",
            city="Bucharest",
            county="Bucharest",
            postal_code="010101",
            country="România",
        )
        now = timezone.now()
        subscription = self._create_aligned_subscription("COUNTRY", now)

        RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        cycle = BillingCycle.objects.get(subscription=subscription)
        self.assertEqual(cycle.proforma.bill_to_country, "RO")

    def test_recurring_proforma_uses_one_address_for_tax_and_snapshot(self) -> None:
        romanian_address = SimpleNamespace(
            address_line1="Strada Test 1",
            address_line2="",
            city="Bucharest",
            county="Bucharest",
            postal_code="010101",
            country="România",
        )
        german_address = SimpleNamespace(
            address_line1="Teststrasse 2",
            address_line2="",
            city="Berlin",
            county="Berlin",
            postal_code="10115",
            country="Germany",
        )
        now = timezone.now()
        subscription = self._create_aligned_subscription("ONE-ADDRESS", now)

        with patch.object(
            Customer,
            "get_billing_address",
            side_effect=[romanian_address, german_address],
        ) as get_billing_address:
            result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(result["proformas_created"], 1)
        self.assertEqual(get_billing_address.call_count, 1)
        cycle = BillingCycle.objects.get(subscription=subscription)
        self.assertEqual(cycle.proforma.bill_to_country, "RO")
        self.assertEqual(cycle.proforma.tax_cents, 2_100)

    def test_recurring_run_reports_active_auto_renew_service_without_subscription(self) -> None:
        now = timezone.now()
        Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            service_name="Unmanaged legacy service",
            username=f"legacy{uuid.uuid4().hex[:8]}",
            billing_cycle="monthly",
            price=Decimal("100.00"),
            auto_renew=True,
            status="active",
            activated_at=now - timedelta(days=30),
            expires_at=now,
        )

        result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(result["unmanaged_services"], 1)
        self.assertTrue(any("no PRAHO subscription" in error for error in result["errors"]))

    def test_proforma_preparation_isolates_failure_to_one_collection_group(self) -> None:
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        now = timezone.now()
        first_subscription = self._create_aligned_subscription("FAILGROUP", now)
        second_subscription = self._create_aligned_subscription("GOODGROUP", now)
        second_subscription.next_charge_at = now + timedelta(days=8)
        second_subscription.save(update_fields=["next_charge_at", "updated_at"])
        real_calculate_vat = TaxService.calculate_vat_for_document
        calls = 0

        def fail_first_group(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("group-specific VAT failure")
            return real_calculate_vat(*args, **kwargs)

        with patch(
            "apps.common.tax_service.TaxService.calculate_vat_for_document",
            side_effect=fail_first_group,
        ):
            result = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)

        self.assertEqual(result["subscriptions_checked"], 2)
        self.assertEqual(result["proformas_created"], 1)
        self.assertEqual(result["cycles_prepared"], 1)
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("group-specific VAT failure", result["errors"][0])
        prepared_cycles = BillingCycle.objects.filter(
            subscription__in=[first_subscription, second_subscription],
            collection_status="prepared",
        )
        self.assertEqual(prepared_cycles.count(), 1)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_paid_trial_renewal_converts_to_active_and_advances_entitlement_once(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        trial_end = timezone.now()
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            service_name="Trial Hosting",
            username=f"trial{uuid.uuid4().hex[:8]}",
            billing_cycle="monthly",
            price=Decimal("100.00"),
            status="active",
            activated_at=trial_end - timedelta(days=14),
            expires_at=trial_end,
        )
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            service=service,
            currency=self.currency,
            subscription_number=f"SUB-TRIAL-{uuid.uuid4().hex[:6].upper()}",
            status="trialing",
            billing_cycle="monthly",
            unit_price_cents=10_000,
            quantity=1,
            trial_start=trial_end - timedelta(days=14),
            trial_end=trial_end,
            current_period_start=trial_end - timedelta(days=14),
            current_period_end=trial_end,
            next_billing_date=trial_end,
            billing_anchor_day=trial_end.day,
            next_proforma_at=trial_end - timedelta(days=1),
            next_charge_at=trial_end - timedelta(hours=1),
            saved_payment_method=self.payment_method,
            payment_authorization=self.authorization,
            auto_payment_enabled=True,
        )

        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=trial_end)
        self.assertEqual(preparation["proformas_created"], 1, preparation)
        proforma = ProformaInvoice.objects.get(meta__source="recurring_billing")
        cycle = BillingCycle.objects.get(subscription=subscription)
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_trial_conversion_301"
        )
        mock_create_gateway.return_value = gateway

        collection = RecurringBillingOrchestrator.collect_due_proformas(as_of=trial_end)
        self.assertEqual(collection["payments_created"], 1, collection)
        payment = Payment.objects.get(gateway_txn_id="pi_trial_conversion_301")
        payload = {
            "data": {
                "object": {
                    "id": payment.gateway_txn_id,
                    "amount_received": payment.amount_cents,
                    "currency": payment.currency.code.lower(),
                    "customer": self.payment_method.stripe_customer_id,
                    "payment_method": self.payment_method.stripe_payment_method_id,
                    "metadata": {
                        "proforma_id": str(proforma.id),
                        "proforma_number": proforma.number,
                        "customer_id": str(self.customer.id),
                        "platform": "PRAHO",
                        "source": "recurring_billing",
                        "payment_attempt": "1",
                    },
                }
            }
        }
        processor = StripeWebhookProcessor()

        first_success, first_message = processor.handle_payment_intent_event(
            "payment_intent.succeeded",
            payload,
        )
        self.assertTrue(first_success, first_message)
        subscription.refresh_from_db()
        service.refresh_from_db()
        cycle.refresh_from_db()
        first_paid_through = subscription.current_period_end
        first_entitlement_at = cycle.entitlement_applied_at
        self.assertEqual(subscription.status, "active")
        self.assertTrue(subscription.trial_converted)
        self.assertIsNotNone(subscription.started_at)
        self.assertEqual(first_paid_through, cycle.period_end)
        self.assertEqual(service.expires_at, cycle.period_end)

        second_success, second_message = processor.handle_payment_intent_event(
            "payment_intent.succeeded",
            payload,
        )
        self.assertTrue(second_success, second_message)
        subscription.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual(subscription.current_period_end, first_paid_through)
        self.assertEqual(cycle.entitlement_applied_at, first_entitlement_at)

    def test_unpaid_expired_trial_cancels_subscription_and_expires_service(self) -> None:
        trial_end = timezone.now() - timedelta(minutes=1)
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            service_name="Expired Trial Hosting",
            username=f"expiredtrial{uuid.uuid4().hex[:8]}",
            billing_cycle="monthly",
            price=Decimal("100.00"),
            status="active",
            activated_at=trial_end - timedelta(days=14),
            expires_at=trial_end,
        )
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            service=service,
            currency=self.currency,
            subscription_number=f"SUB-EXPIRED-{uuid.uuid4().hex[:6].upper()}",
            status="trialing",
            billing_cycle="monthly",
            unit_price_cents=10_000,
            quantity=1,
            trial_start=trial_end - timedelta(days=14),
            trial_end=trial_end,
            current_period_start=trial_end - timedelta(days=14),
            current_period_end=trial_end,
            next_billing_date=trial_end,
        )

        with patch.object(
            Subscription.objects,
            "select_for_update",
            wraps=Subscription.objects.select_for_update,
        ) as lock_subscription:
            processed = SubscriptionLifecycleService.handle_expired_trials(as_of=timezone.now())

        self.assertEqual(processed, 1)
        lock_subscription.assert_called()
        subscription.refresh_from_db()
        service.refresh_from_db()
        self.assertEqual(subscription.status, "cancelled")
        self.assertEqual(subscription.cancellation_reason, "non_payment")
        self.assertIsNotNone(subscription.ended_at)
        self.assertEqual(service.status, "expired")
        self.assertFalse(service.auto_renew)
        self.assertEqual(BillingCycle.objects.filter(subscription=subscription).count(), 0)

    def test_period_end_cancellation_expires_linked_service_and_disables_renewal(self) -> None:
        self.subscription.cancel_at_period_end = True
        self.subscription.current_period_end = timezone.now() - timedelta(minutes=1)
        self.subscription.save(update_fields=["cancel_at_period_end", "current_period_end", "updated_at"])

        processed = SubscriptionLifecycleService.finalize_period_end_cancellations()

        self.assertEqual(processed, 1)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.status, "cancelled")
        self.assertEqual(self.service.status, "expired")
        self.assertFalse(self.service.auto_renew)

    def test_period_end_cancellation_still_finalizes_after_subscription_becomes_past_due(self) -> None:
        """A payment failure must not strand an already scheduled cancellation."""
        self.subscription.cancel_at_period_end = True
        self.subscription.current_period_end = timezone.now() - timedelta(minutes=1)
        self.subscription.save(update_fields=["cancel_at_period_end", "current_period_end", "updated_at"])
        self.subscription.mark_payment_failed()

        processed = SubscriptionLifecycleService.finalize_period_end_cancellations()

        self.assertEqual(processed, 1)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.status, "cancelled")
        self.assertEqual(self.service.status, "expired")
        self.assertFalse(self.service.auto_renew)

    def test_expired_payment_grace_uses_service_fsm_to_suspend_hosting(self) -> None:
        self.subscription.mark_payment_failed()
        self.subscription.grace_period_ends_at = timezone.now() - timedelta(minutes=1)
        self.subscription.save(update_fields=["grace_period_ends_at", "updated_at"])

        processed = SubscriptionLifecycleService.handle_grace_period_expirations()

        self.assertEqual(processed, 1)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.status, "paused")
        self.assertEqual(self.service.status, "suspended")
        self.assertEqual(self.service.suspension_reason, "payment_overdue")

    @patch("apps.billing.subscription_service.get_max_payment_retries", return_value=2)
    def test_paused_nonpayment_subscription_cancels_after_retry_limit(self, _mock_retry_limit: MagicMock) -> None:
        """Failures after suspension must still reach terminal nonpayment cancellation."""
        self.subscription.mark_payment_failed()
        self.subscription.grace_period_ends_at = timezone.now() - timedelta(minutes=1)
        self.subscription.save(update_fields=["grace_period_ends_at", "updated_at"])
        SubscriptionLifecycleService.handle_grace_period_expirations()
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.status, "paused")

        self.subscription.mark_payment_failed()
        processed = SubscriptionLifecycleService.handle_grace_period_expirations()

        self.assertEqual(processed, 1)
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.status, "cancelled")
        self.assertEqual(self.service.status, "suspended")
        self.assertFalse(self.service.auto_renew)

    def test_async_failure_convergence_counts_a_new_attempt_while_subscription_is_paused(self) -> None:
        """A decline after suspension must still advance the dunning retry counter."""
        from apps.billing.payment_convergence import converge_recurring_payment_failure  # noqa: PLC0415

        self.subscription.mark_payment_failed()
        self.subscription.grace_period_ends_at = timezone.now() - timedelta(minutes=1)
        self.subscription.save(update_fields=["grace_period_ends_at", "updated_at"])
        SubscriptionLifecycleService.handle_grace_period_expirations()
        payment = self._create_pending_invoice_payment("pi_paused_async_decline_301")
        self.subscription.refresh_from_db()
        failed_before = self.subscription.failed_payment_count

        processed = converge_recurring_payment_failure(payment)

        self.assertEqual(processed, 1)
        self.subscription.refresh_from_db()
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.subscription.status, "paused")
        self.assertEqual(self.subscription.failed_payment_count, failed_before + 1)
        self.assertEqual(self.billing_cycle.collection_status, "past_due")

    def test_definitive_decline_converges_into_dunning_only_once(self) -> None:
        """Duplicate handling of one failed Payment must not consume two retry slots."""
        from apps.billing.payment_service import _mark_invoice_payment_attempt_failed  # noqa: PLC0415

        policy = PaymentRetryPolicy.objects.create(
            name="Definitive decline retry policy",
            retry_intervals_days=[1, 3],
            max_attempts=2,
            is_active=True,
            is_default=True,
        )
        payment = self._create_pending_invoice_payment("pi_duplicate_definitive_decline_301")
        original_created_at = timezone.now() - timedelta(days=10)
        Payment.objects.filter(pk=payment.pk).update(created_at=original_created_at)

        _mark_invoice_payment_attempt_failed(payment.id, "card declined")
        _mark_invoice_payment_attempt_failed(payment.id, "card declined")

        payment.refresh_from_db()
        self.subscription.refresh_from_db()
        self.billing_cycle.refresh_from_db()
        self.assertEqual(payment.status, "failed")
        self.assertEqual(self.subscription.failed_payment_count, 1)
        self.assertEqual(self.billing_cycle.collection_status, "past_due")
        retry = PaymentRetryAttempt.objects.get(payment=payment)
        self.assertEqual(retry.policy, policy)
        self.assertEqual(retry.attempt_number, 1)
        self.assertEqual(retry.status, "pending")
        self.assertIsNotNone(payment.failed_at)
        assert payment.failed_at is not None
        self.assertEqual(retry.scheduled_at, payment.failed_at + timedelta(days=1))
        self.assertNotEqual(retry.scheduled_at, original_created_at + timedelta(days=1))

    def test_definitive_proforma_decline_schedules_exactly_one_retry(self) -> None:
        """A failed fixed renewal must enter collection without relying on invoice dunning."""
        from apps.billing.payment_service import _mark_invoice_payment_attempt_failed  # noqa: PLC0415

        policy = PaymentRetryPolicy.objects.create(
            name="Proforma decline retry policy",
            retry_intervals_days=[1, 3],
            max_attempts=2,
            is_active=True,
            is_default=True,
        )
        now = timezone.now()
        subscription = self._create_aligned_subscription("RETRY", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        cycle = BillingCycle.objects.get(subscription=subscription)
        payment = Payment.objects.create(
            customer=self.customer,
            proforma=cycle.proforma,
            currency=self.currency,
            amount_cents=cycle.proforma.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_failed_proforma_retry_301",
            status="pending",
            meta={"source": "recurring_billing"},
        )

        _mark_invoice_payment_attempt_failed(payment.id, "card declined")
        _mark_invoice_payment_attempt_failed(payment.id, "duplicate delivery")

        payment.refresh_from_db()
        subscription.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual(payment.status, "failed")
        self.assertEqual(subscription.failed_payment_count, 1)
        self.assertEqual(cycle.collection_status, "past_due")
        retry = PaymentRetryAttempt.objects.get(payment=payment)
        self.assertEqual(retry.policy, policy)
        self.assertEqual(retry.attempt_number, 1)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_confirmed_cancellation_converges_into_dunning_only_once(self, gateway_factory: MagicMock) -> None:
        """Synchronous confirmation must not depend on a later webhook to enter dunning."""
        payment = self._create_pending_invoice_payment("pi_confirmed_cancel_301")
        gateway = MagicMock()
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="canceled",
            error="card declined",
            amount_received=None,
            currency=None,
            customer_id=None,
            payment_method_id=None,
            metadata={},
        )
        gateway_factory.return_value = gateway

        first = PaymentService.confirm_payment(payment.gateway_txn_id or "")
        second = PaymentService.confirm_payment(payment.gateway_txn_id or "")

        self.assertTrue(first["success"])
        self.assertTrue(second["success"])
        self.subscription.refresh_from_db()
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.subscription.failed_payment_count, 1)
        self.assertEqual(self.billing_cycle.collection_status, "past_due")

    def test_late_renewal_payment_restores_only_payment_suspended_service(self) -> None:
        self.subscription.mark_payment_failed()
        self.subscription.grace_period_ends_at = timezone.now() - timedelta(minutes=1)
        self.subscription.save(update_fields=["grace_period_ends_at", "updated_at"])
        SubscriptionLifecycleService.handle_grace_period_expirations()
        payment = self._create_pending_invoice_payment("pi_late_grace_recovery_301")

        result = PaymentSuccessService.converge_gateway_success(
            payment.gateway_txn_id or "",
            self._succeeded_gateway_result(),
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.status, "active")
        self.assertEqual(self.service.status, "active")
        self.assertEqual(self.service.suspension_reason, "")
        self.assertEqual(self.service.expires_at, self.billing_cycle.period_end)

    def test_renewal_payment_does_not_clear_nonpayment_unrelated_suspension(self) -> None:
        self.subscription.mark_payment_failed()
        self.service.suspend(reason="abuse_review")
        self.service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
        payment = self._create_pending_invoice_payment("pi_abuse_suspension_301")

        result = PaymentSuccessService.converge_gateway_success(
            payment.gateway_txn_id or "",
            self._succeeded_gateway_result(),
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.subscription.status, "active")
        self.assertEqual(self.service.status, "suspended")
        self.assertEqual(self.service.suspension_reason, "abuse_review")
        self.assertEqual(self.service.expires_at, self.billing_cycle.period_end)

    def test_gateway_boolean_amount_is_not_accepted_as_one_cent(self) -> None:
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=1,
            payment_method="stripe",
            gateway_txn_id="pi_boolean_amount_301",
        )

        error = PaymentSuccessService._validate_gateway_facts(
            payment,
            {"amount_received": True, "currency": self.currency.code},
        )

        self.assertIsNotNone(error)
        assert error is not None
        self.assertIn("amount", error.lower())

    def test_early_success_webhook_recovers_exact_unlinked_recurring_attempt(self) -> None:
        """A webhook racing the local PI-ID save must not strand a successful charge."""
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id=None,
            idempotency_key=f"invoice:{self.invoice.id}:stripe:race",
            meta={
                "invoice_id": str(self.invoice.id),
                "invoice_number": self.invoice.number,
                "customer_id": str(self.customer.id),
                "platform": "PRAHO",
                "source": "recurring_billing",
                "gateway": "stripe",
                "stripe_customer_id": self.payment_method.stripe_customer_id,
                "stripe_payment_method_id": self.payment_method.stripe_payment_method_id,
            },
        )

        result = PaymentSuccessService.converge_gateway_success(
            "pi_early_success_race_301",
            self._succeeded_gateway_result(),
        )

        self.assertTrue(result.is_ok(), result)
        payment.refresh_from_db()
        self.invoice.refresh_from_db()
        self.assertEqual(payment.gateway_txn_id, "pi_early_success_race_301")
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(self.invoice.status, "paid")

    def test_early_failure_webhook_recovers_exact_unlinked_recurring_attempt(self) -> None:
        """A decline racing the local PI-ID save must not strand a pending attempt."""
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        PaymentRetryPolicy.objects.create(
            name="Early failure retry policy",
            retry_intervals_days=[1, 3],
            max_attempts=2,
            is_active=True,
            is_default=True,
        )
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id=None,
            idempotency_key=f"invoice:{self.invoice.id}:stripe:failure-race",
            meta={
                "invoice_id": str(self.invoice.id),
                "invoice_number": self.invoice.number,
                "customer_id": str(self.customer.id),
                "platform": "PRAHO",
                "source": "recurring_billing",
                "gateway": "stripe",
                "stripe_customer_id": self.payment_method.stripe_customer_id,
                "stripe_payment_method_id": self.payment_method.stripe_payment_method_id,
            },
        )
        payload = {
            "data": {
                "object": {
                    "id": "pi_early_failure_race_301",
                    "amount": self.invoice.total_cents,
                    "currency": self.currency.code.lower(),
                    "customer": self.payment_method.stripe_customer_id,
                    "payment_method": self.payment_method.stripe_payment_method_id,
                    "metadata": {
                        "invoice_id": str(self.invoice.id),
                        "invoice_number": self.invoice.number,
                        "customer_id": str(self.customer.id),
                        "platform": "PRAHO",
                        "source": "recurring_billing",
                        "payment_attempt": "1",
                    },
                    "last_payment_error": {"message": "card declined"},
                }
            }
        }

        accepted, message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.payment_failed",
            payload,
        )

        self.assertTrue(accepted, message)
        payment.refresh_from_db()
        self.subscription.refresh_from_db()
        self.assertEqual(payment.gateway_txn_id, "pi_early_failure_race_301")
        self.assertEqual(payment.status, "failed")
        self.assertEqual(self.subscription.failed_payment_count, 1)
        self.assertTrue(PaymentRetryAttempt.objects.filter(payment=payment).exists())

    def test_unmatched_recurring_success_webhook_is_not_acknowledged_as_external(self) -> None:
        """A charged PRAHO renewal without local state must be retried and alerted."""
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        facts = self._succeeded_gateway_result()
        payload = {
            "data": {
                "object": {
                    "id": "pi_missing_local_recurring_301",
                    "amount_received": facts["amount_received"],
                    "currency": facts["currency"],
                    "customer": facts["customer_id"],
                    "payment_method": facts["payment_method_id"],
                    "metadata": facts["metadata"],
                }
            }
        }

        accepted, message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded",
            payload,
        )

        self.assertFalse(accepted)
        self.assertIn("not found", message.lower())

    def test_unmatched_recurring_failure_webhook_is_not_acknowledged_as_external(self) -> None:
        """A PRAHO renewal decline without local state must be retried and alerted."""
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        facts = self._succeeded_gateway_result()
        payload = {
            "data": {
                "object": {
                    "id": "pi_missing_local_failure_301",
                    "amount": facts["amount_received"],
                    "currency": facts["currency"],
                    "customer": facts["customer_id"],
                    "payment_method": facts["payment_method_id"],
                    "metadata": facts["metadata"],
                    "last_payment_error": {"message": "card declined"},
                }
            }
        }

        accepted, message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.payment_failed",
            payload,
        )

        self.assertFalse(accepted)
        self.assertIn("not found", message.lower())

    def test_collection_releases_document_locks_before_calling_gateway(self) -> None:
        now = timezone.now()
        self._create_aligned_subscription("UNLOCKED", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        outer_savepoint_depth = len(connection.savepoint_ids)
        gateway_call_savepoint_depth: list[int] = []

        def record_transaction_depth(**_kwargs: object) -> PaymentIntentResult:
            gateway_call_savepoint_depth.append(len(connection.savepoint_ids))
            return _intent_result(payment_intent_id="pi_unlocked_collection_301")

        with patch(
            "apps.billing.payment_service.PaymentService.create_payment_intent_for_proforma",
            side_effect=record_transaction_depth,
        ):
            result = RecurringBillingOrchestrator.collect_due_proformas(as_of=now + timedelta(days=8))

        self.assertEqual(result["payments_created"], 1)
        self.assertEqual(gateway_call_savepoint_depth, [outer_savepoint_depth])

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_definitive_renewal_decline_enters_grace_and_waits_for_dunning_scheduler(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("DECLINED", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        cycle = BillingCycle.objects.get(subscription=subscription)
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = PaymentIntentResult(
            success=False,
            payment_intent_id="",
            client_secret=None,
            error="card declined",
            retryable=False,
        )
        mock_create_gateway.return_value = gateway

        first = RecurringBillingOrchestrator.collect_due_proformas(as_of=now + timedelta(days=8))
        second = RecurringBillingOrchestrator.collect_due_proformas(as_of=now + timedelta(days=8))

        self.assertEqual(first["payments_failed"], 1, first)
        self.assertEqual(second["proformas_checked"], 0, second)
        gateway.create_off_session_payment_intent.assert_called_once()
        subscription.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual(subscription.status, "past_due")
        self.assertEqual(subscription.failed_payment_count, 1)
        self.assertIsNotNone(subscription.grace_period_ends_at)
        self.assertEqual(cycle.collection_status, "past_due")

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_early_renewal_decline_starts_grace_only_at_paid_through_boundary(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("EARLY-DECLINE", now)
        paid_through = now + timedelta(days=14)
        subscription.current_period_end = paid_through
        subscription.save(update_fields=["current_period_end", "updated_at"])
        subscription.service.expires_at = paid_through
        subscription.service.save(update_fields=["expires_at", "updated_at"])
        PaymentRetryPolicy.objects.create(
            name="Early decline retry policy",
            retry_intervals_days=[1, 3],
            max_attempts=2,
            is_active=True,
            is_default=True,
        )
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        cycle = BillingCycle.objects.get(subscription=subscription)
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = PaymentIntentResult(
            success=False,
            payment_intent_id="",
            client_secret=None,
            error="card declined",
            retryable=False,
        )
        mock_create_gateway.return_value = gateway

        collection = RecurringBillingOrchestrator.collect_due_proformas(as_of=now + timedelta(days=8))

        self.assertEqual(collection["payments_failed"], 1, collection)
        subscription.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual(subscription.status, "active")
        self.assertEqual(subscription.failed_payment_count, 1)
        self.assertIsNone(subscription.grace_period_ends_at)
        self.assertEqual(cycle.collection_status, "past_due")
        self.assertEqual(PaymentRetryAttempt.objects.filter(payment__proforma=cycle.proforma).count(), 1)

        boundary_run = cycle.period_start + timedelta(minutes=1)
        marked = RecurringBillingOrchestrator.mark_overdue_renewals(as_of=boundary_run)

        self.assertEqual(marked, 1)
        subscription.refresh_from_db()
        self.assertEqual(subscription.status, "past_due")
        self.assertEqual(
            subscription.grace_period_ends_at,
            boundary_run + timedelta(days=subscription.grace_period_days),
        )

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_asynchronous_renewal_failure_enters_grace_exactly_once(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        now = timezone.now()
        policy = PaymentRetryPolicy.objects.create(
            name="Async decline retry policy",
            retry_intervals_days=[1, 3],
            max_attempts=2,
            is_active=True,
            is_default=True,
        )
        subscription = self._create_aligned_subscription("ASYNC-DECLINE", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        cycle = BillingCycle.objects.get(subscription=subscription)
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_async_decline_301"
        )
        mock_create_gateway.return_value = gateway
        collection = RecurringBillingOrchestrator.collect_due_proformas(as_of=now + timedelta(days=8))
        self.assertEqual(collection["payments_created"], 1)
        payload = {
            "data": {
                "object": {
                    "id": "pi_async_decline_301",
                    "last_payment_error": {"message": "insufficient funds"},
                }
            }
        }
        processor = StripeWebhookProcessor()

        first = processor.handle_payment_intent_event("payment_intent.payment_failed", payload)
        second = processor.handle_payment_intent_event("payment_intent.payment_failed", payload)

        self.assertTrue(first[0], first[1])
        self.assertTrue(second[0], second[1])
        subscription.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual(subscription.status, "past_due")
        self.assertEqual(subscription.failed_payment_count, 1)
        self.assertIsNotNone(subscription.grace_period_ends_at)
        self.assertEqual(cycle.collection_status, "past_due")
        payment = Payment.objects.get(gateway_txn_id="pi_async_decline_301")
        retry = PaymentRetryAttempt.objects.get(payment=payment)
        self.assertEqual(retry.policy, policy)
        self.assertEqual(retry.attempt_number, 1)

    def test_unpaid_manual_renewal_enters_grace_at_paid_through_boundary(self) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("MANUAL", now)
        subscription.auto_payment_enabled = False
        subscription.saved_payment_method = None
        subscription.payment_authorization = None
        subscription.save(
            update_fields=["auto_payment_enabled", "saved_payment_method", "payment_authorization", "updated_at"]
        )
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        cycle = BillingCycle.objects.get(subscription=subscription)

        marked = RecurringBillingOrchestrator.mark_overdue_renewals(as_of=cycle.period_start + timedelta(minutes=1))

        self.assertEqual(marked, 1)
        subscription.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual(subscription.status, "past_due")
        self.assertEqual(subscription.failed_payment_count, 0)
        self.assertIsNotNone(subscription.grace_period_ends_at)
        self.assertEqual(cycle.collection_status, "past_due")

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_cancelled_subscription_cannot_create_a_fixed_renewal_charge(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("CANCELLED", now)
        RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        cycle = BillingCycle.objects.get(subscription=subscription)
        subscription.cancel(at_period_end=False)

        result = PaymentService.create_payment_intent_for_proforma(
            cycle.proforma_id,
            self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("status", result["error"].lower())
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_period_end_cancellation_cannot_charge_a_prepared_renewal(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("PERIOD-END-CANCEL", now)
        RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        cycle = BillingCycle.objects.get(subscription=subscription)
        subscription.cancel(at_period_end=True)

        result = PaymentService.create_payment_intent_for_proforma(
            cycle.proforma_id,
            self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("scheduled for cancellation", result["error"].lower())
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_disabled_service_auto_renew_cannot_charge_a_prepared_renewal(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("NO-AUTO-RENEW", now)
        RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        cycle = BillingCycle.objects.get(subscription=subscription)
        subscription.service.auto_renew = False
        subscription.service.save(update_fields=["auto_renew", "updated_at"])

        result = PaymentService.create_payment_intent_for_proforma(
            cycle.proforma_id,
            self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("renewal disabled", result["error"].lower())
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_terminal_service_cannot_charge_a_prepared_renewal(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("EXPIRED-SERVICE", now)
        RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        cycle = BillingCycle.objects.get(subscription=subscription)
        Service.objects.filter(pk=subscription.service_id).update(status="expired")

        result = PaymentService.create_payment_intent_for_proforma(
            cycle.proforma_id,
            self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("service status expired", result["error"].lower())
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_authorization_withdrawn_during_proforma_attempt_setup_fails_before_collection(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("WITHDRAW-RACE", now)
        RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        cycle = BillingCycle.objects.get(subscription=subscription)
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_must_not_charge_proforma_after_withdrawal"
        )

        def withdraw_before_final_revalidation(_gateway_name: str) -> MagicMock:
            self.authorization.withdraw(actor=None, reason="Concurrent withdrawal", at=timezone.now())
            self.authorization.save(update_fields=["status", "withdrawn_at", "updated_at"])
            return gateway

        mock_create_gateway.side_effect = withdraw_before_final_revalidation

        result = PaymentService.create_payment_intent_for_proforma(
            cycle.proforma_id,
            self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("authorization", result["error"].lower())
        gateway.create_off_session_payment_intent.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_proforma_gateway_bound_attempt_wins_over_newer_unbound_duplicate(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("IDEMPOTENT", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        cycle = BillingCycle.objects.get(subscription=subscription)
        assert cycle.proforma is not None
        proforma = cycle.proforma
        bound = Payment.objects.create(
            proforma=proforma,
            customer=self.customer,
            payment_method="stripe",
            amount_cents=proforma.total_cents,
            currency=self.currency,
            status="pending",
            gateway_txn_id="pi_existing_proforma_attempt",
            idempotency_key=f"proforma:{proforma.id}:stripe:1",
            meta={"client_secret": "sec_existing_proforma_attempt"},
        )
        Payment.objects.create(
            proforma=proforma,
            customer=self.customer,
            payment_method="stripe",
            amount_cents=proforma.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"proforma:{proforma.id}:stripe:2",
            meta={
                "source": "recurring_billing",
                "stripe_payment_method_id": self.payment_method.stripe_payment_method_id,
            },
        )

        result = PaymentService.create_payment_intent_for_proforma(
            proforma_id=proforma.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_intent_id"], bound.gateway_txn_id)
        self.assertEqual(result["client_secret"], "sec_existing_proforma_attempt")
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_proforma_idempotency_collision_with_another_payment_fails_closed(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("COLLISION", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        proforma = BillingCycle.objects.get(subscription=subscription).proforma
        assert proforma is not None
        collision = Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=1,
            currency=self.currency,
            status="pending",
            idempotency_key=f"proforma:{proforma.id}:stripe:1",
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_must_not_bind_collision"
        )
        mock_create_gateway.return_value = gateway

        result = PaymentService.create_payment_intent_for_proforma(
            proforma_id=proforma.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("idempotency", result["error"].lower())
        mock_create_gateway.assert_not_called()
        collision.refresh_from_db()
        self.assertIsNone(collision.gateway_txn_id)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_proforma_intent_aborts_when_document_changes_before_gateway_call(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        now = timezone.now()
        subscription = self._create_aligned_subscription("DOCUMENT-RACE", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        proforma = BillingCycle.objects.get(subscription=subscription).proforma
        assert proforma is not None
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_must_not_charge_converted_proforma"
        )

        def convert_proforma_before_gateway(_gateway_name: str) -> MagicMock:
            ProformaInvoice.objects.filter(pk=proforma.pk).update(status="converted")
            return gateway

        mock_create_gateway.side_effect = convert_proforma_before_gateway

        result = PaymentService.create_payment_intent_for_proforma(
            proforma_id=proforma.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("document changed", result["error"].lower())
        gateway.create_off_session_payment_intent.assert_not_called()
        automatic_attempt = Payment.objects.get(proforma=proforma, payment_method="stripe")
        self.assertEqual(automatic_attempt.status, "failed")

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_grouped_proforma_charge_converts_and_advances_each_service_once(  # noqa: PLR0915  # End-to-end financial state proof
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        now = timezone.now()
        first_subscription = self._create_aligned_subscription("ONE", now)
        second_subscription = self._create_aligned_subscription("TWO", now)
        preparation = RecurringBillingOrchestrator.prepare_due_proformas(as_of=now)
        self.assertEqual(preparation["proformas_created"], 1)
        proforma = ProformaInvoice.objects.get()
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_grouped_proforma_301"
        )
        mock_create_gateway.return_value = gateway

        first_collection = RecurringBillingOrchestrator.collect_due_proformas(as_of=now + timedelta(days=8))
        second_collection = RecurringBillingOrchestrator.collect_due_proformas(as_of=now + timedelta(days=8))

        self.assertEqual(first_collection["payments_created"], 1)
        self.assertEqual(second_collection["payments_created"], 0)
        payment = Payment.objects.get(gateway_txn_id="pi_grouped_proforma_301")
        self.assertEqual(payment.proforma_id, proforma.id)
        self.assertIsNone(payment.invoice_id)
        self.assertEqual(payment.amount_cents, proforma.total_cents)
        gateway.create_off_session_payment_intent.assert_called_once()
        cycles = list(BillingCycle.objects.filter(proforma=proforma).order_by("subscription_id"))
        self.assertEqual(len(cycles), 2)
        self.assertTrue(all(cycle.collection_status == "processing" for cycle in cycles))

        payload = {
            "data": {
                "object": {
                    "id": payment.gateway_txn_id,
                    "amount_received": payment.amount_cents,
                    "currency": payment.currency.code.lower(),
                    "customer": self.payment_method.stripe_customer_id,
                    "payment_method": self.payment_method.stripe_payment_method_id,
                    "metadata": {
                        "proforma_id": str(proforma.id),
                        "proforma_number": proforma.number,
                        "customer_id": str(self.customer.id),
                        "platform": "PRAHO",
                        "source": "recurring_billing",
                        "payment_attempt": "1",
                    },
                }
            }
        }
        success1, message1 = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded",
            payload,
        )
        self.assertTrue(success1, message1)

        payment.refresh_from_db()
        proforma.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertIsNotNone(payment.invoice_id)
        self.assertEqual(proforma.status, "converted")
        invoice = payment.invoice
        assert invoice is not None
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(invoice.lines.count(), 2)
        cycles = list(BillingCycle.objects.filter(proforma=proforma).order_by("subscription_id"))
        self.assertTrue(all(cycle.invoice_id == invoice.id for cycle in cycles))
        self.assertTrue(all(cycle.collection_status == "paid" for cycle in cycles))
        self.assertTrue(all(cycle.entitlement_applied_at is not None for cycle in cycles))
        first_subscription.refresh_from_db()
        second_subscription.refresh_from_db()
        first_subscription.service.refresh_from_db()
        second_subscription.service.refresh_from_db()
        cycles_by_subscription = {cycle.subscription_id: cycle for cycle in cycles}
        self.assertEqual(
            first_subscription.current_period_end,
            cycles_by_subscription[first_subscription.id].period_end,
        )
        self.assertEqual(
            second_subscription.current_period_end,
            cycles_by_subscription[second_subscription.id].period_end,
        )
        self.assertEqual(first_subscription.service.expires_at, first_subscription.current_period_end)
        self.assertEqual(second_subscription.service.expires_at, second_subscription.current_period_end)

        success2, message2 = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded",
            payload,
        )
        self.assertTrue(success2, message2)
        first_subscription.refresh_from_db()
        second_subscription.refresh_from_db()
        self.assertEqual(
            first_subscription.current_period_end,
            cycles_by_subscription[first_subscription.id].period_end,
        )
        self.assertEqual(
            second_subscription.current_period_end,
            cycles_by_subscription[second_subscription.id].period_end,
        )

    def test_global_collection_switch_fails_closed(self) -> None:
        SettingsService.update_setting(
            key="billing.recurring_auto_collection_enabled",
            value=False,
            reason="Exercise kill switch",
        )

        with patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway") as gateway_factory:
            result = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )

        self.assertFalse(result["success"])
        self.assertIn("disabled", result["error"])
        gateway_factory.assert_not_called()
        self.assertFalse(Payment.objects.filter(invoice=self.invoice).exists())

    def test_withdrawn_authorization_fails_closed(self) -> None:
        self.authorization.withdraw(actor=None, reason="Test mandate withdrawal", at=timezone.now())
        self.authorization.save(update_fields=["status", "withdrawn_at", "updated_at"])

        with patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway") as gateway_factory:
            result = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )

        self.assertFalse(result["success"])
        self.assertIn("authorization", result["error"])
        gateway_factory.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_authorization_withdrawn_during_attempt_setup_fails_before_gateway_collection(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_must_not_charge_after_withdrawal"
        )

        def withdraw_before_final_revalidation(_gateway_name: str) -> MagicMock:
            self.authorization.withdraw(actor=None, reason="Concurrent withdrawal", at=timezone.now())
            self.authorization.save(update_fields=["status", "withdrawn_at", "updated_at"])
            return gateway

        mock_create_gateway.side_effect = withdraw_before_final_revalidation

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("authorization", result["error"].lower())
        gateway.create_off_session_payment_intent.assert_not_called()

    def test_subscription_auto_payment_enrollment_fails_closed(self) -> None:
        self.subscription.auto_payment_enabled = False
        self.subscription.save(update_fields=["auto_payment_enabled", "updated_at"])

        with patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway") as gateway_factory:
            result = PaymentService.create_payment_intent_for_invoice(
                invoice_id=self.invoice.id,
                payment_method_id=self.payment_method.stripe_payment_method_id,
            )

        self.assertFalse(result["success"])
        self.assertIn("not enrolled", result["error"])
        gateway_factory.assert_not_called()

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_invoice_intent_uses_authoritative_values_and_links_payment(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result()
        mock_create_gateway.return_value = gateway

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertTrue(result["success"], result)
        gateway.create_off_session_payment_intent.assert_called_once_with(
            document_id=str(self.invoice.id),
            document_type="invoice",
            amount_cents=12_100,
            currency="RON",
            customer_id="cus_recurring_301",
            payment_method_id="pm_recurring_301",
            metadata={
                "invoice_id": str(self.invoice.id),
                "invoice_number": self.invoice.number,
                "customer_id": str(self.customer.id),
                "platform": "PRAHO",
                "source": "recurring_billing",
                "payment_attempt": "1",
            },
            idempotency_key=f"invoice:{self.invoice.id}:stripe:1",
        )
        payment = Payment.objects.get(gateway_txn_id="pi_invoice_301")
        self.assertEqual(payment.invoice, self.invoice)
        self.assertEqual(payment.customer, self.customer)
        self.assertEqual(payment.amount_cents, self.invoice.total_cents)
        self.assertEqual(payment.currency, self.currency)
        self.assertEqual(payment.status, "pending")
        self.assertEqual(payment.idempotency_key, f"invoice:{self.invoice.id}:stripe:1")

    @patch("apps.billing.signals._handle_payment_failure")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_invoice_intent_aborts_when_offline_payment_wins_before_gateway_call(
        self,
        mock_create_gateway: MagicMock,
        mock_handle_payment_failure: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_must_not_charge_settled_invoice"
        )

        def settle_invoice_before_gateway(_gateway_name: str) -> MagicMock:
            offline_payment = Payment.objects.create(
                invoice=self.invoice,
                customer=self.customer,
                payment_method="bank",
                amount_cents=self.invoice.total_cents,
                currency=self.currency,
            )
            offline_payment.succeed()
            offline_payment.save(update_fields=["status", "updated_at"])
            return gateway

        mock_create_gateway.side_effect = settle_invoice_before_gateway

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("balance changed", result["error"].lower())
        gateway.create_off_session_payment_intent.assert_not_called()
        automatic_attempt = Payment.objects.get(invoice=self.invoice, payment_method="stripe")
        self.assertEqual(automatic_attempt.status, "failed")
        self.customer.refresh_from_db()
        credit_event_types = {event["event_type"] for event in self.customer.meta.get("credit_history", [])}
        self.assertNotIn("failed_payment", credit_event_types)
        mock_handle_payment_failure.assert_not_called()

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_repeated_invoice_intent_reuses_one_pending_payment(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result()
        mock_create_gateway.return_value = gateway

        first = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )
        second = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertTrue(first["success"])
        self.assertEqual(second, first)
        gateway.create_off_session_payment_intent.assert_called_once()
        self.assertEqual(Payment.objects.filter(invoice=self.invoice).count(), 1)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_invoice_idempotency_collision_with_another_payment_fails_closed(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        collision = Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=1,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:1",
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_must_not_bind_invoice_collision"
        )
        mock_create_gateway.return_value = gateway

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("idempotency", result["error"].lower())
        mock_create_gateway.assert_not_called()
        collision.refresh_from_db()
        self.assertIsNone(collision.gateway_txn_id)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_recurring_document_payment_rejects_non_stripe_gateway(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
            gateway="bank",
        )

        self.assertFalse(result["success"])
        self.assertIn("stripe", result["error"].lower())
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_invoice_gateway_bound_attempt_wins_over_newer_unbound_duplicate(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        bound = Payment.objects.create(
            invoice=self.invoice,
            customer=self.customer,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            gateway_txn_id="pi_existing_invoice_attempt",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:1",
            meta={"client_secret": "sec_existing_invoice_attempt"},
        )
        Payment.objects.create(
            invoice=self.invoice,
            customer=self.customer,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:2",
            meta={
                "source": "recurring_billing",
                "stripe_payment_method_id": self.payment_method.stripe_payment_method_id,
            },
        )

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_intent_id"], bound.gateway_txn_id)
        self.assertEqual(result["client_secret"], "sec_existing_invoice_attempt")
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_pending_payment_without_gateway_id_is_not_reused(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        Payment.objects.create(
            invoice=self.invoice,
            customer=self.customer,
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            gateway_txn_id=None,
        )

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("gateway transaction ID", result["error"])
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_partially_paid_invoice_charges_only_remaining_balance(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        Payment.objects.create(
            invoice=self.invoice,
            customer=self.customer,
            payment_method="bank",
            amount_cents=5_000,
            currency=self.currency,
            status="succeeded",
            gateway_txn_id="bank_partial_301",
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(payment_intent_id="pi_remaining_301")
        mock_create_gateway.return_value = gateway

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertTrue(result["success"], result)
        gateway.create_off_session_payment_intent.assert_called_once()
        self.assertEqual(gateway.create_off_session_payment_intent.call_args.kwargs["amount_cents"], 7_100)
        self.assertEqual(Payment.objects.get(gateway_txn_id="pi_remaining_301").amount_cents, 7_100)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_gateway_success_without_intent_id_marks_attempt_failed(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(payment_intent_id="")
        mock_create_gateway.return_value = gateway

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("payment intent ID", result["error"])
        payment = Payment.objects.get(invoice=self.invoice)
        self.assertEqual(payment.status, "failed")

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_decline_records_failed_attempt_and_next_retry_uses_new_key(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.side_effect = [
            PaymentIntentResult(
                success=False,
                payment_intent_id="",
                client_secret=None,
                error="card declined",
            ),
            _intent_result(payment_intent_id="pi_retry_301"),
        ]
        mock_create_gateway.return_value = gateway

        first = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )
        second = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(first["success"])
        self.assertTrue(second["success"], second)
        attempts = list(Payment.objects.filter(invoice=self.invoice).order_by("created_at"))
        self.assertEqual([payment.status for payment in attempts], ["failed", "pending"])
        self.assertEqual(
            [payment.idempotency_key for payment in attempts],
            [f"invoice:{self.invoice.id}:stripe:1", f"invoice:{self.invoice.id}:stripe:2"],
        )
        self.assertEqual(
            [call.kwargs["idempotency_key"] for call in gateway.create_off_session_payment_intent.call_args_list],
            [f"invoice:{self.invoice.id}:stripe:1", f"invoice:{self.invoice.id}:stripe:2"],
        )

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_uncertain_gateway_failure_retries_same_pending_attempt_and_key(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        gateway = MagicMock()
        uncertain = PaymentIntentResult(
            success=False,
            payment_intent_id="",
            client_secret=None,
            error="connection interrupted",
            retryable=True,
        )
        gateway.create_off_session_payment_intent.side_effect = [
            uncertain,
            _intent_result(payment_intent_id="pi_recovered_301"),
        ]
        mock_create_gateway.return_value = gateway

        first = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )
        pending_after_uncertain_result = Payment.objects.get(invoice=self.invoice)
        self.assertEqual(pending_after_uncertain_result.status, "pending")
        self.assertIsNone(pending_after_uncertain_result.gateway_txn_id)
        self.assertEqual(
            pending_after_uncertain_result.idempotency_key,
            f"invoice:{self.invoice.id}:stripe:1",
        )
        second = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(first["success"])
        self.assertTrue(second["success"], second)
        payment = Payment.objects.get(invoice=self.invoice)
        self.assertEqual(payment.status, "pending")
        self.assertEqual(payment.gateway_txn_id, "pi_recovered_301")
        self.assertEqual(payment.idempotency_key, f"invoice:{self.invoice.id}:stripe:1")
        self.assertEqual(
            [call.kwargs["idempotency_key"] for call in gateway.create_off_session_payment_intent.call_args_list],
            [f"invoice:{self.invoice.id}:stripe:1", f"invoice:{self.invoice.id}:stripe:1"],
        )

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_invoice_intent_rejects_another_customers_payment_method(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        other_customer = Customer.objects.create(
            name="Other Customer SRL",
            customer_type="company",
            company_name="Other Customer SRL",
            primary_email="other@example.ro",
            status="active",
        )
        other_method = CustomerPaymentMethod.objects.create(
            customer=other_customer,
            method_type="stripe_card",
            stripe_customer_id="cus_other_301",
            stripe_payment_method_id="pm_other_301",
            display_name="Other Visa",
            last_four="4444",
            is_active=True,
        )

        result = PaymentService.create_payment_intent_for_invoice(
            invoice_id=self.invoice.id,
            payment_method_id=other_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("active Stripe payment method", result["error"])
        mock_create_gateway.assert_not_called()
        self.assertFalse(Payment.objects.filter(invoice=self.invoice).exists())

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_recurring_payment_charges_saved_method_and_marks_invoice_paid(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result()
        gateway.confirm_payment.return_value = self._succeeded_gateway_result()
        mock_create_gateway.return_value = gateway

        intent = PaymentService.create_payment_intent_for_invoice(
            self.invoice.id,
            self.payment_method.stripe_payment_method_id,
        )
        result = PaymentService.confirm_payment(
            intent["payment_intent_id"],
            customer_id=self.customer.id,
        )

        self.assertTrue(result["success"], result)
        payment = Payment.objects.get(invoice=self.invoice)
        self.assertEqual(payment.status, "succeeded")
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.billing_cycle.refresh_from_db()
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.billing_cycle.collection_status, "paid")
        self.assertEqual(self.billing_cycle.status, "active")
        self.assertIsNotNone(self.billing_cycle.entitlement_applied_at)
        self.assertEqual(self.subscription.current_period_start, self.billing_cycle.period_start)
        self.assertEqual(self.subscription.current_period_end, self.billing_cycle.period_end)
        self.assertEqual(self.subscription.last_payment_amount_cents, self.invoice.total_cents)
        self.assertEqual(self.service.expires_at, self.billing_cycle.period_end)

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_paid_fixed_cycle_uses_configured_invoice_lead_from_paid_through_boundary(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        setting_result = SettingsService.update_setting(
            key="billing.invoice_generation_lead_days",
            value=21,
            reason="renewal schedule test",
        )
        self.assertTrue(setting_result.is_ok(), setting_result)
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_next_renewal_schedule_305"
        )
        gateway.confirm_payment.return_value = self._succeeded_gateway_result()
        mock_create_gateway.return_value = gateway

        intent = PaymentService.create_payment_intent_for_invoice(
            self.invoice.id,
            self.payment_method.stripe_payment_method_id,
        )
        result = PaymentService.confirm_payment(
            intent["payment_intent_id"],
            customer_id=self.customer.id,
        )

        self.assertTrue(result["success"], result)
        self.subscription.refresh_from_db()
        self.assertEqual(
            self.subscription.next_proforma_at,
            self.billing_cycle.period_end - timedelta(days=21),
        )
        self.assertEqual(
            self.subscription.next_charge_at,
            self.billing_cycle.period_end - timedelta(days=7),
        )

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_postpaid_usage_invoice_uses_the_subscription_mandate(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        BillingCycle.objects.filter(pk=self.billing_cycle.pk).update(
            invoice=None,
            usage_invoice=self.invoice,
            status="invoiced",
            collection_status="paid",
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_usage_invoice_301"
        )
        mock_create_gateway.return_value = gateway

        result = PaymentService.create_payment_intent_for_invoice(
            self.invoice.id,
            self.payment_method.stripe_payment_method_id,
        )

        self.assertTrue(result["success"], result)
        payment = Payment.objects.get(invoice=self.invoice)
        self.assertEqual(payment.amount_cents, self.invoice.total_cents)

    def test_paid_usage_invoice_finalizes_usage_without_extending_entitlement(self) -> None:
        UsageAggregation.objects.create(
            meter=UsageMeter.objects.create(
                name=f"bandwidth-{uuid.uuid4().hex[:8]}",
                display_name="Bandwidth",
                aggregation_type="sum",
                unit="gb",
            ),
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=self.billing_cycle.period_start,
            period_end=self.billing_cycle.period_end,
            total_value=Decimal("10"),
            overage_value=Decimal("10"),
            charge_cents=self.invoice.subtotal_cents,
            status="invoiced",
        )
        BillingCycle.objects.filter(pk=self.billing_cycle.pk).update(
            invoice=None,
            usage_invoice=self.invoice,
            status="invoiced",
            collection_status="paid",
        )
        paid_through = self.subscription.current_period_end
        service_expires_at = self.service.expires_at
        payment = self._create_pending_invoice_payment("pi_usage_settlement_301")

        result = PaymentSuccessService.converge_gateway_success(
            payment.gateway_txn_id or "",
            self._succeeded_gateway_result(),
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.billing_cycle.refresh_from_db()
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        aggregation = UsageAggregation.objects.get(billing_cycle=self.billing_cycle)
        self.assertEqual(self.billing_cycle.status, "finalized")
        self.assertIsNotNone(self.billing_cycle.finalized_at)
        self.assertEqual(aggregation.status, "finalized")
        self.assertEqual(self.subscription.current_period_end, paid_through)
        self.assertEqual(self.service.expires_at, service_expires_at)
        self.assertIsNone(self.billing_cycle.entitlement_applied_at)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_fixed_renewal_invoice_rejects_non_upcoming_cycle(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        BillingCycle.objects.filter(pk=self.billing_cycle.pk).update(status="closed")

        result = PaymentService.create_payment_intent_for_invoice(
            self.invoice.id,
            self.payment_method.stripe_payment_method_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("upcoming", result["error"].lower())
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentService.create_payment_intent_for_invoice")
    def test_usage_invoice_auto_payment_does_not_require_an_order_id(
        self,
        mock_create_intent: MagicMock,
    ) -> None:
        BillingCycle.objects.filter(pk=self.billing_cycle.pk).update(
            invoice=None,
            usage_invoice=self.invoice,
            status="invoiced",
            collection_status="paid",
        )
        mock_create_intent.return_value = _intent_result(payment_intent_id="pi_usage_task_301")

        result = process_auto_payment(str(self.invoice.id))

        self.assertTrue(result["success"], result)
        mock_create_intent.assert_called_once_with(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

    @patch("apps.billing.payment_service.PaymentService.create_payment_intent_for_invoice")
    def test_overdue_usage_invoice_remains_collectable_after_a_missed_run(
        self,
        mock_create_intent: MagicMock,
    ) -> None:
        BillingCycle.objects.filter(pk=self.billing_cycle.pk).update(
            invoice=None,
            usage_invoice=self.invoice,
            status="invoiced",
            collection_status="paid",
        )
        self.invoice.mark_overdue()
        self.invoice.save(update_fields=["status", "updated_at"])
        mock_create_intent.return_value = _intent_result(payment_intent_id="pi_overdue_usage_task_305")

        result = process_auto_payment(str(self.invoice.id))

        self.assertTrue(result["success"], result)
        mock_create_intent.assert_called_once_with(
            invoice_id=self.invoice.id,
            payment_method_id=self.payment_method.stripe_payment_method_id,
        )

    def test_webhook_rejects_mismatched_gateway_facts_without_advancing_entitlement(self) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        payment = self._create_pending_invoice_payment("pi_webhook_mismatch_301")
        expected = {
            "id": payment.gateway_txn_id,
            "amount_received": payment.amount_cents,
            "currency": payment.currency.code.lower(),
            "customer": self.payment_method.stripe_customer_id,
            "payment_method": self.payment_method.stripe_payment_method_id,
            "metadata": {
                "invoice_id": str(self.invoice.id),
                "invoice_number": self.invoice.number,
                "customer_id": str(self.customer.id),
                "platform": "PRAHO",
                "source": "recurring_billing",
            },
        }
        mismatches = {
            "amount": {"amount_received": payment.amount_cents - 1},
            "currency": {"currency": "eur"},
            "customer": {"customer": "cus_wrong"},
            "payment method": {"payment_method": "pm_wrong"},
            "document": {"metadata": {**expected["metadata"], "invoice_id": "999999"}},
        }
        processor = StripeWebhookProcessor()

        for label, replacement in mismatches.items():
            with self.subTest(label=label):
                payload = {"data": {"object": {**expected, **replacement}}}
                success, message = processor.handle_payment_intent_event(
                    "payment_intent.succeeded",
                    payload,
                )
                self.assertFalse(success)
                self.assertIn("mismatch", message.lower())
                payment.refresh_from_db()
                self.invoice.refresh_from_db()
                self.billing_cycle.refresh_from_db()
                self.service.refresh_from_db()
                self.assertEqual(payment.status, "pending")
                self.assertEqual(self.invoice.status, "issued")
                self.assertEqual(self.billing_cycle.collection_status, "scheduled")
                self.assertIsNone(self.billing_cycle.entitlement_applied_at)
                self.assertEqual(self.service.expires_at, self.subscription.current_period_end)

    def test_duplicate_success_webhook_repairs_once_without_double_extension(self) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        payment = self._create_pending_invoice_payment("pi_webhook_duplicate_301")
        facts = self._succeeded_gateway_result()
        payload = {
            "data": {
                "object": {
                    "id": payment.gateway_txn_id,
                    "amount_received": facts["amount_received"],
                    "currency": facts["currency"],
                    "customer": facts["customer_id"],
                    "payment_method": facts["payment_method_id"],
                    "metadata": facts["metadata"],
                }
            }
        }
        processor = StripeWebhookProcessor()
        Payment.objects.filter(id=payment.id).update(status="succeeded")
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(self.invoice.status, "issued")
        self.assertIsNone(self.billing_cycle.entitlement_applied_at)

        success1, _message1 = processor.handle_payment_intent_event("payment_intent.succeeded", payload)
        self.assertTrue(success1)
        self.billing_cycle.refresh_from_db()
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        first_applied_at = self.billing_cycle.entitlement_applied_at
        paid_through = self.subscription.current_period_end
        service_expires_at = self.service.expires_at
        self.assertIsNotNone(first_applied_at)
        self.assertEqual(self.billing_cycle.collection_status, "paid")
        self.assertEqual(paid_through, self.billing_cycle.period_end)
        self.assertEqual(service_expires_at, self.billing_cycle.period_end)

        success2, _message2 = processor.handle_payment_intent_event("payment_intent.succeeded", payload)

        self.assertTrue(success2)
        self.billing_cycle.refresh_from_db()
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.billing_cycle.entitlement_applied_at, first_applied_at)
        self.assertEqual(self.subscription.current_period_end, paid_through)
        self.assertEqual(self.service.expires_at, service_expires_at)

    def test_period_gap_rolls_back_payment_and_invoice_success(self) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        payment = self._create_pending_invoice_payment("pi_period_gap_301")
        self.billing_cycle.period_start += timedelta(days=1)
        self.billing_cycle.period_end += timedelta(days=1)
        self.billing_cycle.save(update_fields=["period_start", "period_end", "updated_at"])
        facts = self._succeeded_gateway_result()
        payload = {
            "data": {
                "object": {
                    "id": payment.gateway_txn_id,
                    "amount_received": facts["amount_received"],
                    "currency": facts["currency"],
                    "customer": facts["customer_id"],
                    "payment_method": facts["payment_method_id"],
                    "metadata": facts["metadata"],
                }
            }
        }

        success, message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded",
            payload,
        )

        self.assertFalse(success)
        self.assertIn("period gap", message.lower())
        payment.refresh_from_db()
        self.invoice.refresh_from_db()
        self.billing_cycle.refresh_from_db()
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(payment.status, "pending")
        self.assertEqual(self.invoice.status, "issued")
        self.assertEqual(self.billing_cycle.collection_status, "scheduled")
        self.assertIsNone(self.billing_cycle.entitlement_applied_at)
        self.assertNotEqual(self.subscription.current_period_end, self.billing_cycle.period_end)
        self.assertNotEqual(self.service.expires_at, self.billing_cycle.period_end)

    def test_partial_payment_does_not_advance_recurring_entitlement(self) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=1_000,
            payment_method="stripe",
            gateway_txn_id="pi_partial_301",
        )
        payload = {
            "data": {
                "object": {
                    "id": payment.gateway_txn_id,
                    "amount_received": payment.amount_cents,
                    "currency": self.currency.code.lower(),
                }
            }
        }

        success, _message = StripeWebhookProcessor().handle_payment_intent_event(
            "payment_intent.succeeded",
            payload,
        )

        self.assertTrue(success)
        payment.refresh_from_db()
        self.invoice.refresh_from_db()
        self.billing_cycle.refresh_from_db()
        self.subscription.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(self.invoice.status, "issued")
        self.assertEqual(self.billing_cycle.collection_status, "scheduled")
        self.assertIsNone(self.billing_cycle.entitlement_applied_at)
        self.assertNotEqual(self.subscription.current_period_end, self.billing_cycle.period_end)
        self.assertNotEqual(self.service.expires_at, self.billing_cycle.period_end)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_dunning_retry_creates_new_payment_and_never_reconfirms_failed_attempt(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        original = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_failed_original_301",
            status="failed",
            meta={"source": "recurring_billing"},
        )
        policy = PaymentRetryPolicy.objects.create(
            name="Recurring retry policy",
            retry_intervals_days=[1, 3],
            max_attempts=2,
            is_active=True,
            is_default=True,
        )
        retry = PaymentRetryAttempt.objects.create(
            payment=original,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            status="pending",
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(payment_intent_id="pi_retry_new_301")
        gateway.confirm_payment.return_value = self._succeeded_gateway_result()
        mock_create_gateway.return_value = gateway

        result = run_payment_collection()

        self.assertTrue(result["success"], result)
        self.assertEqual(result["successful"], 1)
        original.refresh_from_db()
        retry.refresh_from_db()
        self.assertEqual(original.status, "failed")
        self.assertIsNotNone(retry.result_payment_id)
        assert retry.result_payment is not None
        self.assertNotEqual(retry.result_payment_id, original.id)
        self.assertEqual(retry.result_payment.gateway_txn_id, "pi_retry_new_301")
        self.assertEqual(retry.result_payment.status, "succeeded")
        gateway.confirm_payment.assert_called_once_with("pi_retry_new_301")
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_dunning_retry_resolves_postpaid_usage_invoice_mandate(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        BillingCycle.objects.filter(pk=self.billing_cycle.pk).update(
            invoice=None,
            usage_invoice=self.invoice,
            status="invoiced",
            collection_status="paid",
        )
        original = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_failed_usage_original_301",
            status="failed",
            meta={"source": "recurring_billing"},
        )
        policy = PaymentRetryPolicy.objects.create(
            name="Usage retry policy",
            retry_intervals_days=[1, 3],
            max_attempts=2,
            is_active=True,
            is_default=True,
        )
        retry = PaymentRetryAttempt.objects.create(
            payment=original,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            status="pending",
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_retry_usage_new_301"
        )
        gateway.confirm_payment.return_value = self._succeeded_gateway_result()
        mock_create_gateway.return_value = gateway

        result = run_payment_collection()

        self.assertTrue(result["success"], result)
        self.assertEqual(result["successful"], 1)
        retry.refresh_from_db()
        self.assertIsNotNone(retry.result_payment_id)
        assert retry.result_payment is not None
        self.assertEqual(retry.result_payment.gateway_txn_id, "pi_retry_usage_new_301")
        self.assertEqual(retry.result_payment.status, "succeeded")
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.billing_cycle.status, "finalized")
        self.assertIsNone(self.billing_cycle.entitlement_applied_at)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_definitive_retry_decline_keeps_one_retry_chain_on_original_payment(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        original = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_failed_retry_root_301",
            status="failed",
            meta={"source": "recurring_billing"},
        )
        policy = PaymentRetryPolicy.objects.create(
            name="Declined retry policy",
            retry_intervals_days=[1, 3],
            max_attempts=2,
            is_active=True,
            is_default=True,
        )
        first_retry = PaymentRetryAttempt.objects.create(
            payment=original,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(minutes=1),
            status="pending",
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = PaymentIntentResult(
            success=False,
            payment_intent_id="",
            client_secret=None,
            error="card declined",
            retryable=False,
        )
        mock_create_gateway.return_value = gateway

        result = run_payment_collection()

        self.assertTrue(result["success"], result)
        self.assertEqual(result["failed"], 1)
        first_retry.refresh_from_db()
        self.assertEqual(first_retry.status, "failed")
        self.assertIsNotNone(first_retry.result_payment_id)
        assert first_retry.result_payment is not None
        self.assertEqual(first_retry.result_payment.status, "failed")
        self.assertFalse(PaymentRetryAttempt.objects.filter(payment=first_retry.result_payment).exists())
        self.assertEqual(
            list(
                PaymentRetryAttempt.objects.filter(payment=original)
                .order_by("attempt_number")
                .values_list("attempt_number", flat=True)
            ),
            [1, 2],
        )

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_stale_processing_retry_is_reclaimed_and_resumed_idempotently(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        original = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_stale_retry_root_301",
            status="failed",
            meta={"source": "recurring_billing"},
        )
        policy = PaymentRetryPolicy.objects.create(
            name="Stale retry policy",
            retry_intervals_days=[1],
            max_attempts=1,
            is_active=True,
            is_default=True,
        )
        retry = PaymentRetryAttempt.objects.create(
            payment=original,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(hours=1),
            executed_at=timezone.now() - timedelta(hours=1),
            status="processing",
        )
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_stale_retry_resumed_301"
        )
        gateway.confirm_payment.return_value = self._succeeded_gateway_result()
        mock_create_gateway.return_value = gateway

        result = run_payment_collection()

        self.assertTrue(result["success"], result)
        self.assertEqual(result["successful"], 1)
        retry.refresh_from_db()
        self.assertEqual(retry.status, "success")
        self.assertIsNotNone(retry.result_payment_id)
        gateway.create_off_session_payment_intent.assert_called_once()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_stale_retry_with_succeeded_result_finishes_without_another_charge(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        original = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_stale_succeeded_root_301",
            status="failed",
            meta={"source": "recurring_billing"},
        )
        succeeded_result = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_stale_succeeded_result_301",
            status="succeeded",
            meta={"source": "recurring_billing"},
        )
        policy = PaymentRetryPolicy.objects.create(
            name="Recovered stale retry policy",
            retry_intervals_days=[1],
            max_attempts=1,
            is_active=True,
            is_default=True,
        )
        retry = PaymentRetryAttempt.objects.create(
            payment=original,
            result_payment=succeeded_result,
            policy=policy,
            attempt_number=1,
            scheduled_at=timezone.now() - timedelta(hours=1),
            executed_at=timezone.now() - timedelta(hours=1),
            status="processing",
        )

        result = run_payment_collection()

        self.assertTrue(result["success"], result)
        self.assertEqual(result["successful"], 1)
        self.assertEqual(result["amount_recovered_cents"], succeeded_result.amount_cents)
        retry.refresh_from_db()
        self.assertEqual(retry.status, "success")
        mock_create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_recurring_payment_rejects_gateway_underpayment(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(payment_intent_id="pi_underpayment_301")
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
            amount_received=self.invoice.total_cents - 1,
        )
        mock_create_gateway.return_value = gateway

        intent = PaymentService.create_payment_intent_for_invoice(
            self.invoice.id,
            self.payment_method.stripe_payment_method_id,
        )
        result = PaymentService.confirm_payment(
            intent["payment_intent_id"],
            customer_id=self.customer.id,
        )

        self.assertFalse(result["success"])
        self.assertIn("amount", (result.get("error") or "").lower())
        payment = Payment.objects.get(invoice=self.invoice)
        self.assertEqual(payment.status, "pending")
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "issued")

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_recurring_payment_rejects_success_without_received_amount(
        self,
        mock_create_gateway: MagicMock,
        _mock_log_security_event: MagicMock,
    ) -> None:
        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = _intent_result(
            payment_intent_id="pi_missing_amount_301"
        )
        gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True,
            status="succeeded",
            error=None,
        )
        mock_create_gateway.return_value = gateway

        intent = PaymentService.create_payment_intent_for_invoice(
            self.invoice.id,
            self.payment_method.stripe_payment_method_id,
        )
        result = PaymentService.confirm_payment(
            intent["payment_intent_id"],
            customer_id=self.customer.id,
        )

        self.assertFalse(result["success"])
        self.assertIn("amount", (result.get("error") or "").lower())
        payment = Payment.objects.get(invoice=self.invoice)
        self.assertEqual(payment.status, "pending")
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "issued")


class StripeOffSessionPaymentContractTestCase(TestCase):
    """Pin the Stripe contract required for a saved-method renewal charge."""

    def test_gateway_confirms_saved_method_off_session_with_idempotency(self) -> None:
        stripe = MagicMock()
        stripe.PaymentIntent.create.return_value = MagicMock(
            id="pi_off_session_301",
            client_secret=None,
        )
        gateway = StripeGateway.__new__(StripeGateway)
        gateway.logger = logging.getLogger("test.subscription_invoice_payment")
        gateway._stripe = stripe

        result = gateway.create_off_session_payment_intent(
            document_id="42",
            document_type="invoice",
            amount_cents=12_100,
            currency="RON",
            customer_id="cus_301",
            payment_method_id="pm_301",
            metadata={"invoice_number": "INV-42"},
            idempotency_key="invoice:42:stripe:1",
        )

        self.assertTrue(result["success"])
        stripe.PaymentIntent.create.assert_called_once_with(
            amount=12_100,
            currency="ron",
            customer="cus_301",
            payment_method="pm_301",
            off_session=True,
            confirm=True,
            metadata={
                "invoice_number": "INV-42",
                "praho_invoice_id": "42",
                "platform": "PRAHO",
            },
            statement_descriptor_suffix="PRAHO",
            idempotency_key="invoice:42:stripe:1",
        )


class RecurringBillingSchemaContractTestCase(TestCase):
    """The database model must express ownership and collection authority explicitly."""

    def test_subscription_has_service_method_authorization_and_collection_fields(self) -> None:
        field_names = {field.name for field in Subscription._meta.get_fields()}

        self.assertTrue(
            {
                "service",
                "saved_payment_method",
                "payment_authorization",
                "auto_payment_enabled",
                "billing_anchor_day",
                "next_proforma_at",
                "next_charge_at",
            }.issubset(field_names)
        )

    def test_billing_cycle_separates_period_and_collection_state(self) -> None:
        field_names = {field.name for field in BillingCycle._meta.get_fields()}

        self.assertTrue(
            {
                "collection_status",
                "proforma",
                "entitlement_applied_at",
                "charge_scheduled_at",
                "collection_started_at",
                "paid_at",
            }.issubset(field_names)
        )

    def test_document_lines_link_to_the_billing_cycle_they_collect(self) -> None:
        self.assertIsNotNone(ProformaLine._meta.get_field("billing_cycle"))
        self.assertIsNotNone(InvoiceLine._meta.get_field("billing_cycle"))


class CalendarBillingPeriodTestCase(SimpleTestCase):
    def test_monthly_anchor_clamps_and_returns_to_original_day(self) -> None:
        bucharest = ZoneInfo("Europe/Bucharest")
        january = datetime(2028, 1, 31, 10, 30, tzinfo=bucharest)
        february = next_billing_period_end(january, "monthly", anchor_day=31)
        march = next_billing_period_end(february, "monthly", anchor_day=31)

        self.assertEqual(february, datetime(2028, 2, 29, 10, 30, tzinfo=bucharest))
        self.assertEqual(march, datetime(2028, 3, 31, 10, 30, tzinfo=bucharest))

    def test_yearly_anchor_handles_leap_day(self) -> None:
        bucharest = ZoneInfo("Europe/Bucharest")
        leap_day = datetime(2028, 2, 29, 8, 0, tzinfo=bucharest)

        self.assertEqual(
            next_billing_period_end(leap_day, "yearly", anchor_day=29),
            datetime(2029, 2, 28, 8, 0, tzinfo=bucharest),
        )


class WebhookAttemptMisbindingRegressionTests(TestCase):
    """#305 review CRITICAL: a redelivered failure webhook from an earlier declined attempt
    must never bind to a LATER retry attempt's pending payment — that records a genuinely
    successful charge as failed, strands the customer in dunning, and orphans the real
    success webhook. Recovery is attempt-precise via the payment_attempt metadata marker."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Misbind Test SRL",
            customer_type="company",
            company_name="Misbind Test SRL",
            primary_email="misbind@test.ro",
            status="active",
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number="INV-MISBIND-1",
            currency=self.currency,
            status="issued",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        # Attempt 1: declined, terminal. Attempt 2: pending, awaiting its own intent.
        self.p1 = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=12100,
            currency=self.currency,
            status="failed",
            meta={"source": "recurring_billing", "invoice_id": str(self.invoice.id)},
        )
        self.p2 = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            payment_method="stripe",
            amount_cents=12100,
            currency=self.currency,
            status="pending",
            meta={
                "source": "recurring_billing",
                "invoice_id": str(self.invoice.id),
                "invoice_number": "INV-MISBIND-1",
                "stripe_customer_id": "cus_misbind",
                "stripe_payment_method_id": "pm_misbind",
            },
        )

    def _facts(self, attempt_id: object) -> dict:
        return {
            "metadata": {
                "source": "recurring_billing",
                "invoice_id": str(self.invoice.id),
                "invoice_number": "INV-MISBIND-1",
                "customer_id": str(self.customer.id),
                "payment_attempt": str(attempt_id),
            },
            "amount_received": 12100,
            "currency": "ron",
            "customer_id": "cus_misbind",
            "payment_method_id": "pm_misbind",
        }

    def test_earlier_attempts_webhook_cannot_bind_to_the_later_pending_attempt(self) -> None:
        result = PaymentSuccessService.recover_unlinked_recurring_attempt(
            "pi_from_declined_attempt_1", self._facts(self.p1.id)
        )

        self.assertTrue(result.is_err())
        self.assertIn(str(self.p1.id), result.unwrap_err())
        self.p2.refresh_from_db()
        self.assertEqual(self.p2.status, "pending")
        self.assertFalse(self.p2.gateway_txn_id)

    def test_matching_attempt_marker_still_recovers_the_right_payment(self) -> None:
        result = PaymentSuccessService.recover_unlinked_recurring_attempt(
            "pi_for_attempt_2", self._facts(self.p2.id)
        )

        self.assertTrue(result.is_ok(), f"recovery failed: {result}")
        self.p2.refresh_from_db()
        self.assertEqual(self.p2.gateway_txn_id, "pi_for_attempt_2")


class RecurringChargeAbandonGuardTests(_SubscriptionInvoicePaymentFixture, TestCase):
    """A resumed reservation may already carry a live Stripe intent from a prior
    attempt (worker died before binding, success webhook not yet delivered).
    Abandoning it inline would record a real charge as failed — only a
    freshly-created reservation is provably pre-submit and safe to abandon."""

    def _pending_recurring_payment(self) -> Payment:
        return Payment.objects.create(
            customer=self.customer,
            invoice_id=self.invoice.id,
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status="pending",
            payment_method="stripe",
            idempotency_key=f"invoice:{self.invoice.id}:stripe:guard",
            meta={"source": "recurring_billing"},
        )

    def _disable_kill_switch(self) -> None:
        result = SettingsService.update_setting("billing.recurring_auto_collection_enabled", False)
        assert result.is_ok(), f"Failed to disable recurring collection: {result}"

    def test_resumed_reservation_is_not_abandoned_when_collection_disabled(self) -> None:
        self._disable_kill_switch()
        payment = self._pending_recurring_payment()
        submit_called = {"v": False}

        def _submit() -> PaymentIntentResult:
            submit_called["v"] = True
            return _intent_result(payment_intent_id="pi_should_not_run")

        _result, submitted = _submit_recurring_charge_under_revocation_lock(
            customer_id=self.customer.id,
            payment=payment,
            revalidate=lambda: None,
            submit=_submit,
            reservation_is_resumed=True,
        )

        self.assertFalse(submitted)
        self.assertFalse(submit_called["v"])
        payment.refresh_from_db()
        self.assertEqual(payment.status, "pending")
        self.assertNotIn("reservation_abandoned", payment.meta)

    def test_fresh_reservation_is_abandoned_when_collection_disabled(self) -> None:
        self._disable_kill_switch()
        payment = self._pending_recurring_payment()

        _result, submitted = _submit_recurring_charge_under_revocation_lock(
            customer_id=self.customer.id,
            payment=payment,
            revalidate=lambda: None,
            submit=lambda: _intent_result(payment_intent_id="pi_never"),
            reservation_is_resumed=False,
        )

        self.assertFalse(submitted)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "failed")
        self.assertTrue(payment.meta.get("reservation_abandoned"))

    def test_revalidation_failure_skips_abandon_for_resumed_reservation(self) -> None:
        payment = self._pending_recurring_payment()
        # Force a revalidation failure by expecting a different amount.
        reason = _revalidate_invoice_payment_reservation(
            invoice_id=self.invoice.id,
            payment_id=payment.id,
            expected_amount_cents=payment.amount_cents + 1,
            expected_currency_id=self.currency.code,
            expected_saved_method_id=self.payment_method.id,
            abandon_on_failure=False,
        )

        self.assertIsNotNone(reason)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "pending")
        self.assertNotIn("reservation_abandoned", payment.meta)
