"""Architecture tests for PRAHO-owned subscriptions and usage billing."""

from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from django.urls import NoReverseMatch, reverse
from django_q.models import Schedule

from apps.billing import metering_tasks, usage_invoice_service
from apps.billing import tasks as billing_tasks
from apps.billing.gateways.base import BasePaymentGateway
from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.metering_models import UsageAggregation, UsageMeter
from apps.billing.payment_service import PaymentService
from apps.billing.subscription_models import Subscription, SubscriptionChange
from apps.billing.subscription_service import SubscriptionService
from apps.customers.profile_models import CustomerBillingProfile
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from apps.orders import tasks as order_tasks


class BillingOwnershipContractTestCase(SimpleTestCase):
    """Stripe processes payments; it must not own PRAHO billing state."""

    def test_payment_gateway_contract_has_no_subscription_lifecycle(self) -> None:
        self.assertFalse(hasattr(BasePaymentGateway, "create_subscription"))
        self.assertFalse(hasattr(BasePaymentGateway, "cancel_subscription"))
        self.assertFalse(hasattr(StripeGateway, "create_subscription"))
        self.assertFalse(hasattr(StripeGateway, "cancel_subscription"))

    def test_gateway_has_no_duplicate_or_subscription_webhook_stack(self) -> None:
        self.assertFalse(hasattr(BasePaymentGateway, "handle_webhook_event"))
        self.assertFalse(hasattr(StripeGateway, "handle_webhook_event"))
        self.assertFalse(hasattr(StripeGateway, "_handle_subscription_webhook"))

    def test_canonical_webhook_processor_has_no_stripe_billing_invoice_handler(self) -> None:
        self.assertFalse(hasattr(StripeWebhookProcessor, "handle_invoice_event"))
        self.assertNotIn("invoice.", StripeWebhookProcessor()._event_handlers)

    def test_payment_service_has_no_gateway_subscription_creation(self) -> None:
        self.assertFalse(hasattr(PaymentService, "create_subscription"))

    def test_stripe_subscription_endpoint_is_not_routed(self) -> None:
        with self.assertRaises(NoReverseMatch):
            reverse("billing:api_create_subscription")

    def test_subscription_has_only_praho_payment_references(self) -> None:
        field_names = {field.name for field in Subscription._meta.get_fields()}

        self.assertNotIn("payment_method_id", field_names)
        self.assertNotIn("stripe_subscription_id", field_names)
        self.assertIn("saved_payment_method", field_names)
        self.assertIn("payment_authorization", field_names)

    def test_customer_billing_profile_has_no_staff_controlled_auto_pay_switch(self) -> None:
        field_names = {field.name for field in CustomerBillingProfile._meta.get_fields()}

        self.assertNotIn("auto_payment_enabled", field_names)

    def test_local_usage_models_have_no_stripe_billing_references(self) -> None:
        meter_fields = {field.name for field in UsageMeter._meta.get_fields()}
        aggregation_fields = {field.name for field in UsageAggregation._meta.get_fields()}

        self.assertNotIn("stripe_meter_id", meter_fields)
        self.assertNotIn("stripe_usage_record_id", aggregation_fields)

    def test_only_billing_orchestrator_runs_subscription_renewals(self) -> None:
        self.assertFalse(hasattr(order_tasks, "process_recurring_orders"))
        self.assertFalse(hasattr(metering_tasks, "advance_billing_cycles"))
        self.assertFalse(hasattr(usage_invoice_service, "BillingCycleManager"))

    def test_incomplete_plan_change_engine_is_not_executable(self) -> None:
        """Plan changes need provisioning, renewal-boundary, and fiscal-credit workflows."""
        self.assertFalse(hasattr(SubscriptionService, "change_subscription"))
        self.assertFalse(hasattr(SubscriptionChange, "calculate_proration"))
        self.assertFalse(hasattr(SubscriptionChange, "apply"))

    @patch("apps.billing.tasks.AuditService.log_simple_event")
    @patch(
        "apps.billing.recurring_billing.RecurringBillingOrchestrator.mark_overdue_renewals",
        return_value=0,
    )
    @patch("apps.billing.recurring_billing.RecurringBillingOrchestrator.collect_due_proformas")
    @patch("apps.billing.recurring_billing.RecurringBillingOrchestrator.prepare_due_proformas")
    @patch(
        "apps.billing.subscription_service.SubscriptionLifecycleService.finalize_period_end_cancellations",
        return_value=0,
    )
    def test_daily_billing_prepares_then_collects_praho_proformas(
        self,
        finalize_cancellations,
        prepare_due_proformas,
        collect_due_proformas,
        mark_overdue_renewals,
        _audit,
    ) -> None:
        prepare_due_proformas.return_value = {
            "subscriptions_checked": 3,
            "cycles_prepared": 2,
            "proformas_created": 1,
            "errors": [],
        }
        collect_due_proformas.return_value = {
            "proformas_checked": 1,
            "payments_created": 1,
            "payments_failed": 0,
            "errors": [],
        }

        result = billing_tasks.run_daily_billing()

        self.assertTrue(result["success"])
        finalize_cancellations.assert_called_once_with()
        prepare_due_proformas.assert_called_once_with()
        collect_due_proformas.assert_called_once_with()
        mark_overdue_renewals.assert_called_once_with()


class BillingScheduleContractTestCase(TestCase):
    @patch("apps.provisioning.models.Service.objects")
    def test_setup_refuses_to_replace_renewal_engine_while_services_are_unmanaged(self, service_objects) -> None:
        service_objects.filter.return_value.count.return_value = 2
        Schedule.objects.create(
            name="order-process-recurring",
            func="apps.orders.tasks.process_recurring_orders",
            schedule_type=Schedule.CRON,
            cron="0 1 * * *",
        )

        with self.assertRaisesMessage(RuntimeError, "2 active auto-renew services have no PRAHO subscription"):
            billing_tasks.setup_billing_scheduled_tasks()

        self.assertTrue(Schedule.objects.filter(name="order-process-recurring").exists())
        self.assertFalse(Schedule.objects.filter(name="billing-recurring-orchestrator").exists())

    @patch("apps.billing.metering_tasks.register_scheduled_tasks")
    def test_setup_replaces_retired_schedules_and_registers_local_usage(self, register_usage) -> None:
        Schedule.objects.create(
            name="order-process-recurring",
            func="apps.orders.tasks.process_recurring_orders",
            schedule_type=Schedule.CRON,
            cron="0 1 * * *",
        )
        Schedule.objects.create(
            name="Sync Pending to Stripe",
            func="apps.billing.metering_tasks.sync_pending_to_stripe",
            schedule_type=Schedule.HOURLY,
        )

        result = billing_tasks.setup_billing_scheduled_tasks()

        self.assertFalse(Schedule.objects.filter(name="order-process-recurring").exists())
        self.assertFalse(Schedule.objects.filter(name="Sync Pending to Stripe").exists())
        self.assertEqual(
            Schedule.objects.get(name="billing-recurring-orchestrator").func,
            "apps.billing.tasks.run_daily_billing",
        )
        retry_schedule = Schedule.objects.get(name="billing-payment-retries")
        self.assertEqual(retry_schedule.func, "apps.billing.tasks.run_payment_collection")
        self.assertEqual(retry_schedule.cron, "*/15 * * * *")
        refund_schedule = Schedule.objects.get(name="billing-refund-reconciliation")
        self.assertEqual(refund_schedule.func, "apps.billing.tasks.reconcile_stripe_refunds")
        self.assertEqual(refund_schedule.cron, "45 2 * * *")
        vies_schedule = Schedule.objects.get(name="billing-vies-reverification")
        self.assertEqual(vies_schedule.func, "apps.billing.tasks.reverify_expired_vat_validations")
        self.assertEqual(vies_schedule.cron, "15 2 * * *")
        recurring_reconciliation = Schedule.objects.get(name="billing-recurring-payment-reconciliation")
        self.assertEqual(
            recurring_reconciliation.func,
            "apps.billing.tasks.reconcile_recurring_payment_submissions",
        )
        self.assertEqual(recurring_reconciliation.cron, "*/10 * * * *")
        self.assertEqual(len(result), 8)
        register_usage.assert_called_once_with()
