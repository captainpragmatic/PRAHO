"""Accepted commercial promises cannot be relabelled by model or queryset writes."""

from datetime import timedelta
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone
from django_fsm import ConcurrentTransition, TransitionNotAllowed

from apps.billing.models import Currency, Invoice, InvoiceSequence, Payment, Subscription
from apps.billing.plan_change_models import PlanChange, PlanChangeInterval
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.customers.models import Customer
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan


class _PlanChangeFixture:
    def setUp(self) -> None:
        self.now = timezone.now()
        # TransactionTestCase flushes migration seeds on preserved PostgreSQL DBs.
        InvoiceSequence.objects.get_or_create(scope="default")
        self.customer = Customer.objects.create(name="Plan customer", customer_type="company", status="active")
        self.actor = get_user_model().objects.create_user(email="plan-change@example.test", password="fixture-only")
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.plan = ServicePlan.objects.create(name="Base", plan_type="shared_hosting", price_monthly=80)
        self.product = Product.objects.create(
            name="Base", slug="change-base", product_type="hosting", default_service_plan=self.plan
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            service_name="Example",
            username="changefixture",
            currency=self.currency,
            price=80,
            status="active",
        )
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            service=self.service,
            currency=self.currency,
            unit_price_cents=8000,
            status="active",
            subscription_number="SUB-CHANGE",
            current_period_start=self.now - timedelta(days=15),
            current_period_end=self.now + timedelta(days=15),
            next_billing_date=self.now + timedelta(days=1),
        )

    def change(self, **overrides: object) -> PlanChange:
        values = {
            "customer": self.customer,
            "requested_by": self.actor,
            "service": self.service,
            "subscription": self.subscription,
            "submission_id": uuid4(),
            "request_fingerprint": "a" * 64,
            "from_product": self.product,
            "to_product": self.product,
            "from_plan": self.plan,
            "to_plan": self.plan,
            "currency": self.currency,
            "expected_limit_revision": 1,
            "direction": "upgrade",
            "quoted_at": self.now,
            "expires_at": self.now + timedelta(minutes=15),
            "authority_expires_at": self.now + timedelta(hours=1),
            "effective_at": self.now,
            "current_period_start": self.subscription.current_period_start,
            "current_period_end": self.subscription.current_period_end,
            "old_period_price_cents": 8000,
            "target_period_price_cents": 20000,
            "net_cents": 6000,
            "tax_cents": 1260,
            "total_cents": 7260,
            "quote_snapshot": {"version": 1},
        }
        values.update(overrides)
        return PlanChange.objects.create(**values)


class PlanChangeModelTests(_PlanChangeFixture, TestCase):
    def test_quote_terms_cannot_be_rewritten_by_a_full_save(self) -> None:
        change = self.change()
        for field, value in (
            ("net_cents", 1),
            ("expected_limit_revision", 7),
            ("quote_snapshot", {"version": 2}),
            ("target_period_price_cents", 1),
        ):
            with self.subTest(field=field):
                row = PlanChange.objects.get(pk=change.pk)
                setattr(row, field, value)
                with self.assertRaises(ValidationError):
                    row.save()
        change.refresh_from_db()
        self.assertEqual((change.net_cents, change.expected_limit_revision), (6000, 1))

    def test_queryset_updates_and_deletes_cannot_bypass_fsm_or_quote(self) -> None:
        change = self.change()
        with self.assertRaises(ValidationError):
            PlanChange.objects.filter(pk=change.pk).update(status="completed")
        with self.assertRaises(ValidationError):
            PlanChange.objects.filter(pk=change.pk).delete()
        with self.assertRaises(ValidationError):
            change.delete()

    def test_only_one_active_change_and_actor_submission_are_unique(self) -> None:
        first = self.change()
        with transaction.atomic(), self.assertRaises(IntegrityError):
            self.change()
        first.cancel()
        first.save(update_fields=["status"])
        with transaction.atomic(), self.assertRaises(IntegrityError):
            self.change(submission_id=first.submission_id)
        self.assertIsNotNone(self.change())

    def test_late_money_can_enter_review_without_replacing_a_new_active_quote(self) -> None:
        old = self.change()
        old.expire()
        old.save(update_fields=["status"])
        new = self.change()
        old.require_review()
        old.save(update_fields=["status"])
        self.assertEqual(PlanChange.objects.get(pk=new.pk).status, "quoted")
        self.assertEqual(old.status, "paid_review")

    def test_stale_fsm_save_cannot_erase_a_payment_claim(self) -> None:
        first = self.change()
        stale = PlanChange.objects.get(pk=first.pk)
        first.confirm()
        first.save(update_fields=["status"])
        stale.expire()
        with transaction.atomic(), self.assertRaises(ConcurrentTransition):
            stale.save(update_fields=["status"])
        self.assertEqual(PlanChange.objects.get(pk=first.pk).status, "awaiting_payment")

    def test_payment_in_flight_cannot_be_cancelled_or_expired(self) -> None:
        change = self.change()
        change.confirm()
        change.begin_payment()
        for transition in (change.cancel, change.expire):
            with self.assertRaises(TransitionNotAllowed):
                transition()

    def test_terminal_payment_proof_releases_a_change_without_reopening_money(self) -> None:
        for method in ("cancel_payment", "expire_payment"):
            with self.subTest(method=method), transaction.atomic():
                change = self.change()
                change.confirm()
                change.begin_payment()
                change.save(update_fields=["status"])
                intent_id = "pi_" + uuid4().hex
                payment = Payment.objects.create(
                    customer=self.customer,
                    currency=self.currency,
                    amount_cents=change.total_cents,
                    gateway_txn_id=intent_id,
                    meta={
                        "source": "hosting_plan_change",
                        "plan_change_id": str(change.pk),
                        "plan_change_terminal_proof": "provider_cancelled",
                    },
                )
                payment.fail_payment()
                payment.save(update_fields=["status"])
                PlanChangePaymentAttempt.objects.create(
                    change=change,
                    payment=payment,
                    payload={},
                    payload_hash="a" * 64,
                    idempotency_key=str(uuid4()),
                    state="cancelled",
                    provider_status="canceled",
                    first_submitted_at=self.now,
                    gateway_intent_id=intent_id,
                    submission_count=1,
                )
                getattr(change, method)()
                change.save(update_fields=["status"])
                self.assertEqual(change.status, "cancelled" if method == "cancel_payment" else "expired")
                payment.refresh_from_db()
                self.assertEqual(payment.status, "failed")
                transaction.set_rollback(True)

    def test_cancelled_label_without_provider_proof_cannot_release_application_authority(self) -> None:
        change = self.change()
        change.confirm()
        change.begin_payment()
        change.save(update_fields=["status"])
        payment = Payment.objects.create(
            customer=self.customer, currency=self.currency, amount_cents=change.total_cents
        )
        PlanChangePaymentAttempt.objects.create(
            change=change,
            payment=payment,
            payload={},
            payload_hash="a" * 64,
            idempotency_key=str(uuid4()),
            state="cancelled",
            provider_status="requires_payment_method",
            first_submitted_at=self.now,
        )
        for transition in (change.cancel_payment, change.expire_payment):
            with self.assertRaises(ValidationError):
                transition()
        self.assertEqual(change.status, "payment_in_flight")

    def test_accepted_document_binding_cannot_be_replaced(self) -> None:
        change = self.change()
        documents = [
            Invoice.objects.create(customer=self.customer, currency=self.currency, number=f"BIND-{uuid4().hex}")
            for _ in range(2)
        ]
        change.invoice = documents[0]
        change.save(update_fields=["invoice"])
        change.invoice = documents[1]
        with self.assertRaises(ValidationError):
            change.save(update_fields=["invoice"])
        self.assertEqual(PlanChange.objects.get(pk=change.pk).invoice_id, documents[0].pk)

    def test_unconfirmed_zero_due_quote_cannot_be_applied(self) -> None:
        change = self.change(net_cents=0, tax_cents=0, total_cents=0)
        with self.assertRaises(TransitionNotAllowed):
            change.commit_limits()
        change.confirm()
        change.save(update_fields=["status", "confirmed_at"])
        change.commit_limits()
        self.assertIsNotNone(change.confirmed_at)

    def test_interval_allocations_are_immutable_and_bound_to_exact_span(self) -> None:
        change = self.change()
        part = PlanChangeInterval.objects.create(
            change=change,
            ordinal=0,
            period_start=change.current_period_start,
            period_end=change.current_period_end,
            slice_start=change.quoted_at,
            base_net_cents=8000,
            prior_supplement_cents=0,
            net_cents=6000,
            current_slice=True,
            evidence={"document_id": "source", "fixed_line_id": 1},
        )
        part.net_cents = 100
        with self.assertRaises(ValidationError):
            part.save()
        with self.assertRaises(ValidationError):
            PlanChangeInterval.objects.filter(pk=part.pk).update(net_cents=100)
        with self.assertRaises(ValidationError):
            part.delete()
        self.assertEqual(PlanChangeInterval.objects.get(pk=part.pk).net_cents, 6000)
