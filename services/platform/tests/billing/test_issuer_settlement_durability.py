"""Confirmed fiscal issuance survives settlement failures."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditAlert
from apps.billing.issuers import service
from apps.billing.issuers.base import Issued
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.metering_models import BillingCycle, UsageAggregation, UsageMeter
from apps.billing.models import Currency, Invoice, Payment
from apps.billing.subscription_models import Subscription
from apps.common.types import Result
from apps.products.models import Product
from tests.factories.billing_factories import CustomerFactory
from tests.helpers.task_queue import quiet_task_queue


class IssuedDocumentSettlementTests(TestCase):
    def setUp(self) -> None:
        quiet_task_queue(self)
        quiet = patch("apps.notifications.services.EmailService.send_template_email", return_value="test-delivery")
        quiet.start()
        self.addCleanup(quiet.stop)
        self.customer = CustomerFactory()
        self.currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=0,
            total_cents=10000,
            bill_to_name="Settlement test",
            bill_to_country="DE",
            issuer_provider="smartbill",
        )
        self.token = uuid4()
        self.issuance = ProviderIssuance.objects.create(
            invoice=self.invoice,
            provider="smartbill",
            state=IssuanceState.CLAIMED.value,
            claim_token=self.token,
            claim_expires_at=timezone.now() + timedelta(minutes=10),
            attempts=1,
        )

    def confirm(self) -> Result[str, str]:
        return service._finalize(
            self.invoice.pk,
            self.issuance.pk,
            self.token,
            Issued(series="FCT", number="000123", provider_document_id="20363", response_digest="confirmed"),
        )

    def reconcile(self) -> Result[str, str]:
        return service.reconcile_confirmed_issued(
            self.issuance.pk, series="FCT", number="000123", operator_note="Found in provider UI"
        )

    def quarantine(self) -> None:
        self.issuance.mark_outcome_unknown(reason="Response lost")
        self.issuance.save()

    def fund(self, *, amount_cents: int | None = None) -> Payment:
        payment = Payment(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=self.invoice.total_cents if amount_cents is None else amount_cents,
            payment_method="other",
        )
        payment._defer_document_settlement = True
        payment.succeed()
        payment.save()
        return payment

    def cancelled_renewal(self) -> tuple[Subscription, BillingCycle]:
        now = timezone.now()
        product = Product.objects.create(name="Hosting", slug="settlement-hosting", product_type="shared_hosting")
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=product,
            currency=self.currency,
            status="active",
            unit_price_cents=10000,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            next_billing_date=now,
            cancel_at_period_end=True,
        )
        cycle = BillingCycle.objects.create(
            subscription=subscription,
            invoice=self.invoice,
            period_start=now,
            period_end=now + timedelta(days=30),
            collection_status="processing",
        )
        return subscription, cycle

    def assert_issued_with_failure(self, reason: str) -> None:
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.number, "FCT-000123")
        self.assertEqual(self.invoice.status, "issued")
        self.assertIsNone(self.invoice.paid_at)
        issuance = ProviderIssuance.objects.get(pk=self.issuance.pk)
        self.assertEqual(issuance.state, IssuanceState.ISSUED.value)
        self.assertEqual((issuance.provider_series, issuance.provider_number), ("FCT", "000123"))
        self.assertIsNone(issuance.claim_token)
        self.assertIsNone(issuance.claim_expires_at)
        alert = AuditAlert.objects.get(
            metadata={"source": "provider_issuance_settlement", "invoice_id": self.invoice.pk}
        )
        self.assertEqual((alert.status, alert.severity), ("active", "high"))
        self.assertEqual(alert.evidence["invoice_number"], "FCT-000123")
        self.assertIn(reason, alert.evidence["error"])

    def test_confirmed_issuance_survives_convergence_err_and_can_recover(self) -> None:
        payment = self.fund()
        subscription, cycle = self.cancelled_renewal()
        with self.captureOnCommitCallbacks(execute=True):
            result = self.confirm()
        self.assert_issued_with_failure("no longer permits renewal entitlement")
        self.assertTrue(result.is_ok(), str(result))
        issuance = ProviderIssuance.objects.get(pk=self.issuance.pk)
        self.assertEqual(issuance.provider_document_id, "20363")
        self.assertEqual(issuance.response, {"digest": "confirmed"})
        self.assertEqual(issuance.submissions, 1)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "succeeded")
        cycle.refresh_from_db()
        self.assertIsNone(cycle.entitlement_applied_at)
        self.assertEqual(cycle.collection_status, "processing")

        subscription.cancel_at_period_end = False
        subscription.save(update_fields=["cancel_at_period_end"])
        with self.captureOnCommitCallbacks(execute=True):
            service._settle_issued_document(self.invoice.pk)
        self.invoice.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertIsNotNone(cycle.entitlement_applied_at)
        self.assertEqual(cycle.collection_status, "paid")
        self.assertEqual(ProviderIssuance.objects.get(pk=self.issuance.pk).submissions, 1)
        self.assertEqual(Payment.objects.filter(invoice=self.invoice).count(), 1)

    def test_reconciliation_survives_convergence_err(self) -> None:
        payment = self.fund()
        self.cancelled_renewal()
        self.quarantine()
        with self.captureOnCommitCallbacks(execute=True):
            result = self.reconcile()
        self.assert_issued_with_failure("no longer permits renewal entitlement")
        self.assertTrue(result.is_ok(), str(result))
        issuance = ProviderIssuance.objects.get(pk=self.issuance.pk)
        self.assertIn("Found in provider UI", issuance.last_error)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "succeeded")

    def assert_zero_total_paid(self, *, reconciled: bool) -> None:
        self.invoice.subtotal_cents = 0
        self.invoice.discount_cents = 10000
        self.invoice.total_cents = 0
        self.invoice.save(update_fields=["subtotal_cents", "discount_cents", "total_cents"])
        if reconciled:
            self.quarantine()
        activated: list[Invoice] = []
        with (
            patch("apps.billing.signals._trigger_virtualmin_provisioning_on_payment", side_effect=activated.append),
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = self.reconcile() if reconciled else self.confirm()
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertTrue(result.is_ok(), str(result))
        self.assertEqual(self.invoice.number, "FCT-000123")
        self.assertIsNotNone(self.invoice.paid_at)
        self.assertFalse(Payment.objects.filter(invoice=self.invoice).exists())
        self.assertEqual([invoice.pk for invoice in activated], [self.invoice.pk])

    def test_zero_total_issuance_runs_paid_lifecycle_without_payment(self) -> None:
        self.assert_zero_total_paid(reconciled=False)

    def test_zero_total_reconciliation_runs_paid_lifecycle_without_payment(self) -> None:
        self.assert_zero_total_paid(reconciled=True)

    def test_reconciliation_defers_settlement_until_caller_commits(self) -> None:
        self.fund()
        self.quarantine()
        with self.captureOnCommitCallbacks(execute=True), transaction.atomic():
            result = self.reconcile()
            self.invoice.refresh_from_db()
            self.assertEqual(self.invoice.status, "issued")
            self.assertIsNone(self.invoice.paid_at)
            self.customer.company_name = "Operator attribution committed"
            self.customer.save(update_fields=["company_name"])
        self.assertTrue(result.is_ok(), str(result))
        self.invoice.refresh_from_db()
        self.customer.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertEqual(self.customer.company_name, "Operator attribution committed")

    def test_settlement_database_exception_preserves_confirmed_issuance(self) -> None:
        self.fund()
        with (
            patch.object(Invoice, "update_status_from_payments", side_effect=DatabaseError("Settlement unavailable")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = self.confirm()
        self.assert_issued_with_failure("Settlement unavailable")
        self.assertTrue(result.is_ok(), str(result))

    def usage_records(self) -> tuple[BillingCycle, UsageAggregation]:
        subscription, cycle = self.cancelled_renewal()
        # Postpaid usage settles the completed period without renewing entitlement.
        BillingCycle.objects.filter(pk=cycle.pk).update(
            invoice=None,
            usage_invoice=self.invoice,
            status="invoiced",
            collection_status="paid",
            period_start=subscription.current_period_start,
            period_end=subscription.current_period_end,
        )
        cycle.refresh_from_db()
        aggregation = UsageAggregation.objects.create(
            meter=UsageMeter.objects.create(
                name="settlement-bandwidth", display_name="Bandwidth", aggregation_type="sum", unit="gb"
            ),
            customer=self.customer,
            subscription=subscription,
            billing_cycle=cycle,
            period_start=cycle.period_start,
            period_end=cycle.period_end,
            total_value=Decimal("10"),
            overage_value=Decimal("10"),
            charge_cents=10000,
            status="invoiced",
        )
        return cycle, aggregation

    def recovery_sweep(self) -> dict[str, int]:
        from apps.billing.issuers import tasks  # noqa: PLC0415

        sweep: Callable[[], dict[str, int]] | None = getattr(tasks, "sweep_issued_settlements", None)
        self.assertIsNotNone(sweep, "Issued-invoice settlement recovery sweep is missing")
        assert sweep is not None
        return sweep()

    def test_lost_confirmation_callback_is_recovered_once(self) -> None:
        payments = [self.fund(amount_cents=4000), self.fund(amount_cents=6000)]
        cycle, aggregation = self.usage_records()
        activated: list[Invoice] = []
        with self.captureOnCommitCallbacks(execute=False), transaction.atomic():
            result = self.confirm()
        self.assertTrue(result.is_ok(), str(result))
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "issued")
        self.assertIsNone(self.invoice.paid_at)
        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit",
                side_effect=AssertionError("Resubmitted"),
            ),
            patch("apps.billing.signals._trigger_virtualmin_provisioning_on_payment", side_effect=activated.append),
            self.captureOnCommitCallbacks(execute=True),
        ):
            first = self.recovery_sweep()
            self.invoice.refresh_from_db()
            cycle.refresh_from_db()
            aggregation.refresh_from_db()
            self.assertEqual(self.invoice.status, "paid")
            self.assertEqual((cycle.status, aggregation.status), ("finalized", "finalized"))
            paid_at, finalized_at = self.invoice.paid_at, cycle.finalized_at
            second = self.recovery_sweep()
        self.assertEqual(first, {"settled": 1, "failed": 0, "skipped": 0})
        self.assertEqual(second, {"settled": 0, "failed": 0, "skipped": 0})
        self.invoice.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual((self.invoice.paid_at, cycle.finalized_at), (paid_at, finalized_at))
        self.assertEqual([invoice.pk for invoice in activated], [self.invoice.pk])
        self.assertEqual(ProviderIssuance.objects.get(pk=self.issuance.pk).submissions, 1)
        self.assertEqual(
            list(Payment.objects.filter(invoice=self.invoice).order_by("pk").values_list("pk", flat=True)),
            [payment.pk for payment in payments],
        )

    def test_lost_zero_total_reconciliation_callback_recovers_usage(self) -> None:
        self.invoice.subtotal_cents = 0
        self.invoice.discount_cents = 10000
        self.invoice.total_cents = 0
        self.invoice.save(update_fields=["subtotal_cents", "discount_cents", "total_cents"])
        cycle, aggregation = self.usage_records()
        self.quarantine()
        with self.captureOnCommitCallbacks(execute=False), transaction.atomic():
            result = self.reconcile()
        self.assertTrue(result.is_ok(), str(result))
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "issued")
        with self.captureOnCommitCallbacks(execute=True):
            first = self.recovery_sweep()
            second = self.recovery_sweep()
        self.invoice.refresh_from_db()
        cycle.refresh_from_db()
        aggregation.refresh_from_db()
        self.assertEqual((self.invoice.status, cycle.status, aggregation.status), ("paid", "finalized", "finalized"))
        self.assertFalse(self.invoice.payments.exists())
        self.assertEqual(first, {"settled": 1, "failed": 0, "skipped": 0})
        self.assertEqual(second, {"settled": 0, "failed": 0, "skipped": 0})
        self.assertEqual(ProviderIssuance.objects.get(pk=self.issuance.pk).submissions, 0)

    def test_repeated_recovery_failure_keeps_one_alert_and_can_retry(self) -> None:
        payment = self.fund()
        subscription, cycle = self.cancelled_renewal()
        with self.captureOnCommitCallbacks(execute=False):
            self.confirm()
        for _attempt in range(2):
            self.assertEqual(self.recovery_sweep(), {"settled": 0, "failed": 1, "skipped": 0})
            self.assert_issued_with_failure("no longer permits renewal entitlement")
        self.assertEqual(
            AuditAlert.objects.filter(
                metadata={"source": "provider_issuance_settlement", "invoice_id": self.invoice.pk}
            ).count(),
            1,
        )
        cycle.refresh_from_db()
        self.assertEqual(cycle.collection_status, "processing")
        self.assertIsNone(cycle.entitlement_applied_at)
        subscription.cancel_at_period_end = False
        subscription.save(update_fields=["cancel_at_period_end"])
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(self.recovery_sweep(), {"settled": 1, "failed": 0, "skipped": 0})
        self.invoice.refresh_from_db()
        cycle.refresh_from_db()
        self.assertEqual((self.invoice.status, cycle.collection_status), ("paid", "paid"))
        self.assertIsNotNone(cycle.entitlement_applied_at)
        self.assertEqual(Payment.objects.get(pk=payment.pk).status, "succeeded")
        self.assertEqual(ProviderIssuance.objects.get(pk=self.issuance.pk).submissions, 1)

    def assert_zero_total_usage_finalized(self, *, reconciled: bool) -> None:
        cycle, aggregation = self.usage_records()
        paid_through = Subscription.objects.get(pk=cycle.subscription_id).current_period_end
        self.assert_zero_total_paid(reconciled=reconciled)
        cycle.refresh_from_db()
        aggregation.refresh_from_db()
        self.assertEqual(cycle.status, "finalized")
        self.assertIsNotNone(cycle.finalized_at)
        self.assertEqual(aggregation.status, "finalized")
        self.assertIsNone(cycle.entitlement_applied_at)
        self.assertEqual(Subscription.objects.get(pk=cycle.subscription_id).current_period_end, paid_through)

    def test_zero_total_confirmation_finalizes_usage_records(self) -> None:
        self.assert_zero_total_usage_finalized(reconciled=False)

    def test_zero_total_reconciliation_finalizes_usage_records(self) -> None:
        self.assert_zero_total_usage_finalized(reconciled=True)

    def test_recovery_excludes_unissued_builtin_and_insufficient_funding(self) -> None:
        self.fund()
        with self.captureOnCommitCallbacks(execute=False):
            self.confirm()
        excluded: list[Invoice] = []
        cases = (
            ("partial", "smartbill", True, IssuanceState.ISSUED.value, "succeeded", 9999),
            ("pending", "smartbill", True, IssuanceState.ISSUED.value, "pending", 10000),
            ("builtin", "builtin", True, IssuanceState.ISSUED.value, "succeeded", 10000),
            ("unissued", "smartbill", False, IssuanceState.PENDING.value, "succeeded", 10000),
            ("unknown", "smartbill", False, IssuanceState.OUTCOME_UNKNOWN.value, "succeeded", 10000),
        )
        for name, provider, issued, state, payment_status, amount in cases:
            invoice = Invoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=None,
                issuer_provider=provider,
                subtotal_cents=10000,
                total_cents=10000,
                bill_to_country="DE",
            )
            if issued:
                invoice.number = f"EXCLUDED-{name}"
                invoice.issue()
                invoice.save()
            ProviderIssuance.objects.create(invoice=invoice, provider=provider, state=state)
            payment = Payment(
                customer=self.customer,
                invoice=invoice,
                currency=self.currency,
                amount_cents=amount,
                payment_method="other",
            )
            payment._defer_document_settlement = True
            if payment_status == "succeeded":
                payment.succeed()
            payment.save()
            excluded.append(invoice)
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(self.recovery_sweep(), {"settled": 1, "failed": 0, "skipped": 0})
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        for invoice in excluded:
            expected_status = invoice.status
            invoice.refresh_from_db()
            self.assertEqual(invoice.status, expected_status)
            self.assertIsNone(invoice.paid_at)

    def test_recovery_schedule_is_installed_once_by_setup_command(self) -> None:
        from django_q.models import Schedule  # noqa: PLC0415

        Schedule.objects.all().delete()
        for _run in range(2):
            call_command("setup_scheduled_tasks", billing_only=True, stdout=StringIO())
        schedules = Schedule.objects.filter(name="billing-issued-settlement-sweep")
        self.assertEqual(schedules.count(), 1)
        schedule = schedules.get()
        self.assertEqual(schedule.func, "apps.billing.issuers.tasks.sweep_issued_settlements")
        self.assertEqual((schedule.schedule_type, schedule.minutes, schedule.repeats), (Schedule.MINUTES, 5, -1))

    def test_recovery_registration_failure_fails_setup_command(self) -> None:
        from django_q.models import Schedule  # noqa: PLC0415

        Schedule.objects.all().delete()
        failure = DatabaseError("settlement schedule store unavailable")
        with patch(
            "apps.common.management.commands.setup_scheduled_tasks.setup_issuance_scheduled_tasks",
            side_effect=failure,
            create=True,
        ):
            with self.assertRaisesMessage(CommandError, str(failure)) as caught:
                call_command("setup_scheduled_tasks", billing_only=True, stdout=StringIO())
            self.assertIs(caught.exception.__cause__, failure)
        self.assertFalse(Schedule.objects.filter(name="billing-issued-settlement-sweep").exists())
