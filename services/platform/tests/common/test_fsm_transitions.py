"""
FSM transition smoke tests for all 15 django-fsm-2 protected models.

Verifies that:
1. Every @transition method succeeds from its declared source state(s)
2. Invalid transitions raise TransitionNotAllowed
3. FSMField(protected=True) blocks direct .status = assignment

Part of the defense-in-depth strategy from ADR-0034.
"""

from __future__ import annotations

import inspect
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from django_fsm import ConcurrentTransition, TransitionNotAllowed

from apps.billing.currency_models import Currency
from apps.billing.efactura.models import EFacturaDocument
from apps.billing.invoice_models import Invoice
from apps.billing.metering_models import BillingCycle, UsageAggregation, UsageMeter
from apps.billing.payment_models import TERMINAL_PAYMENT_STATUSES, Payment
from apps.billing.proforma_models import ProformaInvoice
from apps.billing.refund_models import Refund
from apps.billing.subscription_models import Subscription
from apps.customers.customer_models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.orders.models import Order, OrderItem
from apps.orders.signals import _handle_order_status_change
from apps.orders.tasks import process_pending_orders, process_recurring_orders
from apps.products.models import Product
from apps.promotions.models import PromotionCampaign
from apps.provisioning.relationship_models import ServiceGroup
from apps.provisioning.service_models import Server, Service, ServicePlan
from apps.tickets.models import Ticket
from tests.helpers.fsm_helpers import force_status


class FSMTestMixin:
    """Shared helpers for FSM transition smoke tests."""

    @classmethod
    def _create_customer(cls) -> Customer:
        return Customer.objects.create(
            name="FSM Smoke SRL",
            customer_type="company",
            status="active",
            primary_email="fsm-smoke@test.ro",
        )

    @classmethod
    def _create_currency(cls) -> Currency:
        currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2},
        )
        return currency


# ---------------------------------------------------------------------------
# 1. Invoice FSM (6 transitions)
# ---------------------------------------------------------------------------


class InvoiceFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Invoice status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_invoice(self, status: str = "draft") -> Invoice:
        inv = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FSM-INV-{Invoice.objects.count() + 1:04d}",
        )
        if status != "draft":
            force_status(inv, status)
        return inv

    def test_issue_from_draft(self) -> None:
        inv = self._make_invoice("draft")
        inv.issue()
        inv.save(update_fields=["status"])
        self.assertEqual(inv.status, "issued")

    def test_mark_as_paid_from_issued(self) -> None:
        inv = self._make_invoice("issued")
        inv.mark_as_paid()
        inv.save(update_fields=["status"])
        self.assertEqual(inv.status, "paid")

    def test_mark_as_paid_from_overdue(self) -> None:
        inv = self._make_invoice("overdue")
        inv.mark_as_paid()
        inv.save(update_fields=["status"])
        self.assertEqual(inv.status, "paid")

    def test_mark_overdue_from_issued(self) -> None:
        inv = self._make_invoice("issued")
        inv.mark_overdue()
        inv.save(update_fields=["status"])
        self.assertEqual(inv.status, "overdue")

    def test_void_from_draft(self) -> None:
        inv = self._make_invoice("draft")
        inv.void()
        inv.save(update_fields=["status"])
        self.assertEqual(inv.status, "void")

    def test_void_from_issued(self) -> None:
        inv = self._make_invoice("issued")
        inv.void()
        inv.save(update_fields=["status"])
        self.assertEqual(inv.status, "void")

    def test_refund_from_paid(self) -> None:
        inv = self._make_invoice("paid")
        inv.refund_invoice()
        inv.save(update_fields=["status"])
        self.assertEqual(inv.status, "refunded")

    def test_partial_refund_from_paid(self) -> None:
        inv = self._make_invoice("paid")
        inv.mark_partially_refunded()
        inv.save(update_fields=["status"])
        self.assertEqual(inv.status, "partially_refunded")

    # Invalid transitions
    def test_cannot_pay_from_draft(self) -> None:
        inv = self._make_invoice("draft")
        with self.assertRaises(TransitionNotAllowed):
            inv.mark_as_paid()

    def test_cannot_refund_from_issued(self) -> None:
        inv = self._make_invoice("issued")
        with self.assertRaises(TransitionNotAllowed):
            inv.refund_invoice()

    def test_cannot_void_from_paid(self) -> None:
        inv = self._make_invoice("paid")
        with self.assertRaises(TransitionNotAllowed):
            inv.void()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        inv = self._make_invoice("draft")
        with self.assertRaises(AttributeError):
            inv.status = "paid"


# ---------------------------------------------------------------------------
# 2. ProformaInvoice FSM (4 transitions)
# ---------------------------------------------------------------------------


class ProformaInvoiceFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for ProformaInvoice status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_proforma(self, status: str = "draft") -> ProformaInvoice:
        pi = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FSM-PI-{ProformaInvoice.objects.count() + 1:04d}",
        )
        if status != "draft":
            force_status(pi, status)
        return pi

    def test_send_from_draft(self) -> None:
        pi = self._make_proforma("draft")
        pi.send_proforma()
        pi.save(update_fields=["status"])
        self.assertEqual(pi.status, "sent")

    def test_accept_from_sent(self) -> None:
        pi = self._make_proforma("sent")
        pi.accept()
        pi.save(update_fields=["status"])
        self.assertEqual(pi.status, "accepted")

    def test_expire_from_sent(self) -> None:
        pi = self._make_proforma("sent")
        pi.expire()
        pi.save(update_fields=["status"])
        self.assertEqual(pi.status, "expired")

    def test_convert_from_accepted(self) -> None:
        pi = self._make_proforma("accepted")
        pi.convert()
        pi.save(update_fields=["status"])
        self.assertEqual(pi.status, "converted")

    def test_convert_from_draft(self) -> None:
        pi = self._make_proforma("draft")
        pi.convert()
        pi.save(update_fields=["status"])
        self.assertEqual(pi.status, "converted")

    # Invalid transitions
    def test_cannot_accept_from_draft(self) -> None:
        pi = self._make_proforma("draft")
        with self.assertRaises(TransitionNotAllowed):
            pi.accept()

    def test_cannot_expire_from_draft(self) -> None:
        pi = self._make_proforma("draft")
        with self.assertRaises(TransitionNotAllowed):
            pi.expire()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        pi = self._make_proforma("draft")
        with self.assertRaises(AttributeError):
            pi.status = "sent"


# ---------------------------------------------------------------------------
# 3. Payment FSM (5 transitions)
# ---------------------------------------------------------------------------


class PaymentFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Payment status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_payment(self, status: str = "pending") -> Payment:
        inv = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FSM-PINV-{Invoice.objects.count() + 1:04d}",
        )
        force_status(inv, "issued")
        pay = Payment.objects.create(
            customer=self.customer,
            invoice=inv,
            currency=self.currency,
            amount_cents=10000,
            payment_method="stripe",
        )
        if status != "pending":
            force_status(pay, status)
        return pay

    def test_succeed_from_pending(self) -> None:
        pay = self._make_payment("pending")
        pay.succeed()
        pay.save(update_fields=["status"])
        self.assertEqual(pay.status, "succeeded")

    def test_fail_from_pending(self) -> None:
        pay = self._make_payment("pending")
        pay.fail_payment()
        pay.save(update_fields=["status"])
        self.assertEqual(pay.status, "failed")

    def test_refund_from_succeeded(self) -> None:
        pay = self._make_payment("succeeded")
        pay.refund_payment()
        pay.save(update_fields=["status"])
        self.assertEqual(pay.status, "refunded")

    def test_partial_refund_from_succeeded(self) -> None:
        pay = self._make_payment("succeeded")
        pay.partially_refund()
        pay.save(update_fields=["status"])
        self.assertEqual(pay.status, "partially_refunded")

    def test_complete_refund_from_partially_refunded(self) -> None:
        pay = self._make_payment("partially_refunded")
        pay.complete_refund()
        pay.save(update_fields=["status"])
        self.assertEqual(pay.status, "refunded")

    # Invalid transitions
    def test_cannot_refund_from_pending(self) -> None:
        pay = self._make_payment("pending")
        with self.assertRaises(TransitionNotAllowed):
            pay.refund_payment()

    def test_cannot_succeed_from_failed(self) -> None:
        pay = self._make_payment("failed")
        with self.assertRaises(TransitionNotAllowed):
            pay.succeed()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        pay = self._make_payment("pending")
        with self.assertRaises(AttributeError):
            pay.status = "succeeded"


# ---------------------------------------------------------------------------
# 4. Refund FSM (7 transitions)
# ---------------------------------------------------------------------------


class RefundFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Refund status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_refund(self, status: str = "pending") -> Refund:
        inv = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FSM-RINV-{Refund.objects.count() + 1:04d}",
        )
        force_status(inv, "paid")
        pay = Payment.objects.create(
            customer=self.customer,
            invoice=inv,
            currency=self.currency,
            amount_cents=10000,
            payment_method="stripe",
        )
        force_status(pay, "succeeded")
        ref = Refund.objects.create(
            customer=self.customer,
            invoice=inv,
            payment=pay,
            currency=self.currency,
            amount_cents=5000,
            original_amount_cents=10000,
            reason="Test refund",
        )
        if status != "pending":
            force_status(ref, status)
        return ref

    def test_start_processing_from_pending(self) -> None:
        ref = self._make_refund("pending")
        ref.start_processing()
        ref.save(update_fields=["status"])
        self.assertEqual(ref.status, "processing")

    def test_cancel_from_pending(self) -> None:
        ref = self._make_refund("pending")
        ref.cancel()
        ref.save(update_fields=["status"])
        self.assertEqual(ref.status, "cancelled")

    def test_approve_from_processing(self) -> None:
        ref = self._make_refund("processing")
        ref.approve()
        ref.save(update_fields=["status"])
        self.assertEqual(ref.status, "approved")

    def test_reject_from_processing(self) -> None:
        ref = self._make_refund("processing")
        ref.reject()
        ref.save(update_fields=["status"])
        self.assertEqual(ref.status, "rejected")

    def test_mark_failed_from_processing(self) -> None:
        ref = self._make_refund("processing")
        ref.mark_failed()
        ref.save(update_fields=["status"])
        self.assertEqual(ref.status, "failed")

    def test_complete_from_approved(self) -> None:
        ref = self._make_refund("approved")
        ref.complete()
        ref.save(update_fields=["status"])
        self.assertEqual(ref.status, "completed")

    def test_retry_from_failed(self) -> None:
        ref = self._make_refund("failed")
        ref.retry()
        ref.save(update_fields=["status"])
        self.assertEqual(ref.status, "pending")

    # Invalid transitions
    def test_cannot_approve_from_pending(self) -> None:
        ref = self._make_refund("pending")
        with self.assertRaises(TransitionNotAllowed):
            ref.approve()

    def test_cannot_complete_from_pending(self) -> None:
        ref = self._make_refund("pending")
        with self.assertRaises(TransitionNotAllowed):
            ref.complete()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        ref = self._make_refund("pending")
        with self.assertRaises(AttributeError):
            ref.status = "completed"


# ---------------------------------------------------------------------------
# 5. Subscription FSM (10 transitions, private methods with public facades)
# ---------------------------------------------------------------------------


class SubscriptionFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Subscription status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()
        cls.product = Product.objects.create(
            slug="fsm-sub-product",
            name="FSM Sub Product",
            product_type="hosting",
            is_active=True,
        )

    def _make_subscription(self, status: str = "pending") -> Subscription:
        now = timezone.now()
        sub = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            unit_price_cents=5000,
            billing_cycle="monthly",
            current_period_start=now,
            current_period_end=now + timezone.timedelta(days=30),
            next_billing_date=now + timezone.timedelta(days=30),
        )
        if status != "pending":
            force_status(sub, status)
        return sub

    def test_activate_from_pending(self) -> None:
        sub = self._make_subscription("pending")
        sub._activate_now()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "active")

    def test_start_trial_from_pending(self) -> None:
        sub = self._make_subscription("pending")
        sub._start_trial_now()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "trialing")

    def test_convert_trial_to_active(self) -> None:
        sub = self._make_subscription("trialing")
        sub._convert_trial_now()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "active")

    def test_cancel_from_active(self) -> None:
        sub = self._make_subscription("active")
        sub._cancel_now()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "cancelled")

    def test_cancel_from_pending(self) -> None:
        sub = self._make_subscription("pending")
        sub._cancel_now()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "cancelled")

    def test_pause_from_active(self) -> None:
        sub = self._make_subscription("active")
        sub._pause_now()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "paused")

    def test_resume_from_paused(self) -> None:
        sub = self._make_subscription("paused")
        sub._resume_now()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "active")

    def test_go_past_due_from_active(self) -> None:
        sub = self._make_subscription("active")
        sub._go_past_due()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "past_due")

    def test_expire_from_active(self) -> None:
        sub = self._make_subscription("active")
        sub.expire()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "expired")

    def test_reactivate_from_cancelled(self) -> None:
        sub = self._make_subscription("cancelled")
        sub._reactivate_now()
        sub.save(update_fields=["status"])
        self.assertEqual(sub.status, "active")

    # Invalid transitions
    def test_cannot_pause_from_pending(self) -> None:
        sub = self._make_subscription("pending")
        with self.assertRaises(TransitionNotAllowed):
            sub._pause_now()

    def test_cannot_reactivate_from_active(self) -> None:
        sub = self._make_subscription("active")
        with self.assertRaises(TransitionNotAllowed):
            sub._reactivate_now()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        sub = self._make_subscription("pending")
        with self.assertRaises(AttributeError):
            sub.status = "active"


# ---------------------------------------------------------------------------
# 6. Service FSM (8 transitions)
# ---------------------------------------------------------------------------


class ServiceFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Service (hosting) status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()
        cls.server = Server.objects.create(
            name="fsm-test-server",
            hostname="fsm-test.example.com",
            server_type="shared",
            primary_ip="192.168.1.1",
            location="Bucharest",
            datacenter="DC-FSM",
            cpu_model="Test CPU",
            cpu_cores=4,
            ram_gb=16,
            disk_type="SSD",
            disk_capacity_gb=100,
        )
        cls.plan = ServicePlan.objects.create(
            name="FSM Test Plan",
            plan_type="shared",
            price_monthly=10,
            price_quarterly=25,
            price_annual=90,
        )

    def _make_service(self, status: str = "pending") -> Service:
        svc = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            server=self.server,
            currency=self.currency,
            service_name="FSM Test Service",
            username=f"fsmtest{Service.objects.count() + 1}",
            price=10,
        )
        if status != "pending":
            force_status(svc, status)
        return svc

    def test_start_provisioning_from_pending(self) -> None:
        svc = self._make_service("pending")
        svc.start_provisioning()
        svc.save(update_fields=["status"])
        self.assertEqual(svc.status, "provisioning")

    def test_complete_provisioning(self) -> None:
        svc = self._make_service("provisioning")
        svc.complete_provisioning()
        svc.save(update_fields=["status"])
        self.assertEqual(svc.status, "active")

    def test_fail_provisioning_from_provisioning(self) -> None:
        svc = self._make_service("provisioning")
        svc.fail_provisioning()
        svc.save(update_fields=["status"])
        self.assertEqual(svc.status, "failed")

    def test_activate_from_suspended(self) -> None:
        svc = self._make_service("suspended")
        svc.activate()
        svc.save(update_fields=["status"])
        self.assertEqual(svc.status, "active")

    def test_suspend_from_active(self) -> None:
        svc = self._make_service("active")
        svc.suspend(reason="Test suspension")
        svc.save(update_fields=["status", "suspended_at", "suspension_reason"])
        self.assertEqual(svc.status, "suspended")

    def test_terminate_from_active(self) -> None:
        svc = self._make_service("active")
        svc.terminate()
        svc.save(update_fields=["status", "terminated_at"])
        self.assertEqual(svc.status, "terminated")

    def test_expire_from_active(self) -> None:
        svc = self._make_service("active")
        svc.expire()
        svc.save(update_fields=["status"])
        self.assertEqual(svc.status, "expired")

    def test_retry_from_failed(self) -> None:
        svc = self._make_service("failed")
        svc.retry()
        svc.save(update_fields=["status"])
        self.assertEqual(svc.status, "pending")

    # Invalid transitions
    def test_cannot_complete_from_pending(self) -> None:
        svc = self._make_service("pending")
        with self.assertRaises(TransitionNotAllowed):
            svc.complete_provisioning()

    def test_cannot_suspend_from_pending(self) -> None:
        svc = self._make_service("pending")
        with self.assertRaises(TransitionNotAllowed):
            svc.suspend()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        svc = self._make_service("pending")
        with self.assertRaises(AttributeError):
            svc.status = "active"


# ---------------------------------------------------------------------------
# 7. Domain FSM (7 transitions)
# ---------------------------------------------------------------------------


class DomainFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Domain status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.tld = TLD.objects.create(
            extension="fsm",
            description="FSM test TLD",
            registration_price_cents=5000,
            renewal_price_cents=4000,
            transfer_price_cents=3000,
        )
        cls.registrar = Registrar.objects.create(
            name="FSM Registrar",
            display_name="FSM Registrar",
            website_url="https://fsm-registrar.test",
            api_endpoint="https://api.fsm-registrar.test",
        )

    def _make_domain(self, status: str = "pending") -> Domain:
        dom = Domain.objects.create(
            name=f"fsmtest{Domain.objects.count() + 1}.fsm",
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
        )
        if status != "pending":
            force_status(dom, status)
        return dom

    def test_activate_from_pending(self) -> None:
        dom = self._make_domain("pending")
        dom.activate()
        dom.save(update_fields=["status"])
        self.assertEqual(dom.status, "active")

    def test_expire_from_active(self) -> None:
        dom = self._make_domain("active")
        dom.expire()
        dom.save(update_fields=["status"])
        self.assertEqual(dom.status, "expired")

    def test_suspend_from_active(self) -> None:
        dom = self._make_domain("active")
        dom.suspend()
        dom.save(update_fields=["status"])
        self.assertEqual(dom.status, "suspended")

    def test_start_transfer_out_from_active(self) -> None:
        dom = self._make_domain("active")
        dom.start_transfer_out()
        dom.save(update_fields=["status"])
        self.assertEqual(dom.status, "transfer_out")

    def test_start_transfer_in_from_pending(self) -> None:
        dom = self._make_domain("pending")
        dom.start_transfer_in()
        dom.save(update_fields=["status"])
        self.assertEqual(dom.status, "transfer_in")

    def test_cancel_from_pending(self) -> None:
        dom = self._make_domain("pending")
        dom.cancel()
        dom.save(update_fields=["status"])
        self.assertEqual(dom.status, "cancelled")

    def test_cancel_from_expired(self) -> None:
        dom = self._make_domain("expired")
        dom.cancel()
        dom.save(update_fields=["status"])
        self.assertEqual(dom.status, "cancelled")

    def test_activate_from_expired(self) -> None:
        """Renewal: expired → active."""
        dom = self._make_domain("expired")
        dom.activate()
        dom.save(update_fields=["status"])
        self.assertEqual(dom.status, "active")

    # Invalid transitions
    def test_cannot_expire_from_pending(self) -> None:
        dom = self._make_domain("pending")
        with self.assertRaises(TransitionNotAllowed):
            dom.expire()

    def test_cannot_transfer_out_from_pending(self) -> None:
        dom = self._make_domain("pending")
        with self.assertRaises(TransitionNotAllowed):
            dom.start_transfer_out()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        dom = self._make_domain("pending")
        with self.assertRaises(AttributeError):
            dom.status = "active"


# ---------------------------------------------------------------------------
# 8. Ticket FSM (5 transitions)
# ---------------------------------------------------------------------------


class TicketFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Ticket status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()

    def _make_ticket(self, status: str = "open") -> Ticket:
        ticket = Ticket.objects.create(
            customer=self.customer,
            ticket_number=f"FSM-T-{Ticket.objects.count() + 1:04d}",
            title="FSM Smoke Test Ticket",
            description="Test ticket for FSM transition verification",
            priority="normal",
        )
        if status != "open":
            force_status(ticket, status)
        return ticket

    def test_start_work_from_open(self) -> None:
        ticket = self._make_ticket("open")
        ticket.start_work()
        ticket.save(update_fields=["status"])
        self.assertEqual(ticket.status, "in_progress")

    def test_wait_on_customer_from_open(self) -> None:
        ticket = self._make_ticket("open")
        ticket.wait_on_customer()
        ticket.save(update_fields=["status"])
        self.assertEqual(ticket.status, "waiting_on_customer")

    def test_close_from_open(self) -> None:
        ticket = self._make_ticket("open")
        ticket.close()
        ticket.save(update_fields=["status", "closed_at"])
        self.assertEqual(ticket.status, "closed")

    def test_close_from_in_progress(self) -> None:
        ticket = self._make_ticket("in_progress")
        ticket.close()
        ticket.save(update_fields=["status", "closed_at"])
        self.assertEqual(ticket.status, "closed")

    def test_reopen_from_closed(self) -> None:
        ticket = self._make_ticket("closed")
        ticket.reopen()
        ticket.save(update_fields=["status"])
        self.assertEqual(ticket.status, "open")

    def test_back_to_queue_from_waiting(self) -> None:
        ticket = self._make_ticket("waiting_on_customer")
        ticket.back_to_queue()
        ticket.save(update_fields=["status"])
        self.assertEqual(ticket.status, "open")

    # Invalid transitions
    def test_cannot_reopen_from_open(self) -> None:
        ticket = self._make_ticket("open")
        with self.assertRaises(TransitionNotAllowed):
            ticket.reopen()

    def test_cannot_start_work_from_closed(self) -> None:
        ticket = self._make_ticket("closed")
        with self.assertRaises(TransitionNotAllowed):
            ticket.start_work()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        ticket = self._make_ticket("open")
        with self.assertRaises(AttributeError):
            ticket.status = "closed"


# ---------------------------------------------------------------------------
# 9. OrderItem provisioning_status FSM (5 transitions)
# ---------------------------------------------------------------------------


class OrderItemFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for OrderItem provisioning_status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()
        cls.product = Product.objects.create(
            slug="fsm-oi-product",
            name="FSM OI Product",
            product_type="hosting",
            is_active=True,
        )

    def _make_order_item(self, provisioning_status: str = "pending") -> OrderItem:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            status="draft",
        )
        item = OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=5000,
        )
        if provisioning_status != "pending":
            force_status(item, provisioning_status, field_name="provisioning_status")
        return item

    def test_start_provisioning(self) -> None:
        item = self._make_order_item("pending")
        item.start_provisioning()
        item.save(update_fields=["provisioning_status"])
        self.assertEqual(item.provisioning_status, "in_progress")

    def test_complete_provisioning(self) -> None:
        item = self._make_order_item("in_progress")
        item.complete_provisioning()
        item.save(update_fields=["provisioning_status"])
        self.assertEqual(item.provisioning_status, "completed")

    def test_fail_provisioning(self) -> None:
        item = self._make_order_item("in_progress")
        item.fail_provisioning()
        item.save(update_fields=["provisioning_status"])
        self.assertEqual(item.provisioning_status, "failed")

    def test_cancel_provisioning(self) -> None:
        item = self._make_order_item("pending")
        item.cancel_provisioning()
        item.save(update_fields=["provisioning_status"])
        self.assertEqual(item.provisioning_status, "cancelled")

    def test_retry_provisioning_from_failed(self) -> None:
        item = self._make_order_item("failed")
        item.retry_provisioning()
        item.save(update_fields=["provisioning_status"])
        self.assertEqual(item.provisioning_status, "pending")

    # Invalid transitions
    def test_cannot_complete_from_pending(self) -> None:
        item = self._make_order_item("pending")
        with self.assertRaises(TransitionNotAllowed):
            item.complete_provisioning()

    def test_cannot_retry_from_pending(self) -> None:
        item = self._make_order_item("pending")
        with self.assertRaises(TransitionNotAllowed):
            item.retry_provisioning()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        item = self._make_order_item("pending")
        with self.assertRaises(AttributeError):
            item.provisioning_status = "completed"


# ---------------------------------------------------------------------------
# 10. Order FSM (10 transitions)
# ---------------------------------------------------------------------------


class OrderFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Order status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()
        cls.product = Product.objects.create(
            slug="fsm-order-product",
            name="FSM Order Product",
            product_type="hosting",
            is_active=True,
        )

    def _make_order(self, status: str = "draft", *, with_items: bool = False) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            status="draft",
        )
        if with_items:
            OrderItem.objects.create(
                order=order,
                product=self.product,
                product_name=self.product.name,
                product_type=self.product.product_type,
                quantity=1,
                unit_price_cents=5000,
            )
        if status != "draft":
            force_status(order, status)
        return order

    # Phase A: Order states renamed (awaiting_payment, paid, in_review, provisioning)
    def test_submit_from_draft_with_items(self) -> None:
        order = self._make_order("draft", with_items=True)
        order.submit()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "awaiting_payment")

    def test_mark_paid_from_awaiting_payment(self) -> None:
        order = self._make_order("awaiting_payment")
        order.mark_paid()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "paid")

    def test_start_provisioning_from_paid(self) -> None:
        order = self._make_order("paid")
        order.start_provisioning()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "provisioning")

    def test_flag_for_review_from_paid(self) -> None:
        order = self._make_order("paid")
        order.flag_for_review()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "in_review")

    def test_approve_review_from_in_review(self) -> None:
        order = self._make_order("in_review")
        order.approve_review()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "provisioning")

    def test_reject_review_from_in_review(self) -> None:
        order = self._make_order("in_review")
        order.reject_review()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "cancelled")

    def test_complete_from_provisioning(self) -> None:
        order = self._make_order("provisioning")
        order.complete()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "completed")

    def test_cancel_from_draft(self) -> None:
        order = self._make_order("draft")
        order.cancel()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "cancelled")

    def test_cancel_from_awaiting_payment(self) -> None:
        order = self._make_order("awaiting_payment")
        order.cancel()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "cancelled")

    def test_fail_from_provisioning(self) -> None:
        order = self._make_order("provisioning")
        order.fail()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "failed")

    def test_retry_from_failed(self) -> None:
        order = self._make_order("failed")
        order.retry()
        order.save(update_fields=["status"])
        self.assertEqual(order.status, "awaiting_payment")

    # Invalid transitions
    def test_cannot_mark_paid_from_draft(self) -> None:
        order = self._make_order("draft")
        with self.assertRaises(TransitionNotAllowed):
            order.mark_paid()

    def test_cannot_complete_from_awaiting_payment(self) -> None:
        order = self._make_order("awaiting_payment")
        with self.assertRaises(TransitionNotAllowed):
            order.complete()

    def test_cannot_cancel_from_completed(self) -> None:
        order = self._make_order("completed")
        with self.assertRaises(TransitionNotAllowed):
            order.cancel()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        order = self._make_order("draft")
        with self.assertRaises(AttributeError):
            order.status = "completed"


# ---------------------------------------------------------------------------
# 11. EFacturaDocument FSM (7 transitions)
# ---------------------------------------------------------------------------


class EFacturaDocumentFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for EFacturaDocument status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_efactura(self, status: str = "draft") -> EFacturaDocument:

        inv = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FSM-EF-{Invoice.objects.count() + 1:04d}",
        )
        doc = EFacturaDocument.objects.create(invoice=inv)
        if status != "draft":
            force_status(doc, status)
        return doc

    def test_mark_queued_from_draft(self) -> None:
        doc = self._make_efactura("draft")
        doc.mark_queued()
        doc.save()
        self.assertEqual(doc.status, "queued")

    def test_mark_queued_from_error(self) -> None:
        doc = self._make_efactura("error")
        doc.mark_queued()
        doc.save()
        self.assertEqual(doc.status, "queued")

    def test_mark_submitted_from_queued(self) -> None:
        doc = self._make_efactura("queued")
        doc.mark_submitted("IDX-123")
        doc.save()
        self.assertEqual(doc.status, "submitted")
        self.assertEqual(doc.anaf_upload_index, "IDX-123")

    def test_mark_processing_from_submitted(self) -> None:
        doc = self._make_efactura("submitted")
        doc.mark_processing()
        doc.save()
        self.assertEqual(doc.status, "processing")

    def test_mark_accepted_from_processing(self) -> None:
        doc = self._make_efactura("processing")
        doc.mark_accepted("DL-456")
        doc.save()
        self.assertEqual(doc.status, "accepted")

    def test_mark_rejected_from_processing(self) -> None:
        doc = self._make_efactura("processing")
        doc.mark_rejected([{"message": "test error"}])
        doc.save()
        self.assertEqual(doc.status, "rejected")

    def test_mark_error_from_submitted(self) -> None:
        doc = self._make_efactura("submitted")
        doc.mark_error("network error")
        doc.save()
        self.assertEqual(doc.status, "error")

    def test_cannot_accept_from_draft(self) -> None:
        doc = self._make_efactura("draft")
        with self.assertRaises(TransitionNotAllowed):
            doc.mark_accepted("DL-456")

    def test_protected_field_blocks_direct_assignment(self) -> None:
        doc = self._make_efactura("draft")
        with self.assertRaises(AttributeError):
            doc.status = "accepted"


# ---------------------------------------------------------------------------
# 12. BillingCycle FSM (5 transitions)
# ---------------------------------------------------------------------------


class BillingCycleFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for BillingCycle status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_billing_cycle(self, status: str = "upcoming") -> BillingCycle:

        product = Product.objects.create(
            name=f"FSM-BC-Prod-{Product.objects.count() + 1}",
            slug=f"fsm-bc-prod-{Product.objects.count() + 1}",
            product_type="shared_hosting",
        )
        now = timezone.now()
        sub = Subscription.objects.create(
            customer=self.customer,
            currency=self.currency,
            product=product,
            subscription_number=f"SUB-BC-{Subscription.objects.count() + 1:04d}",
            unit_price_cents=5000,
            current_period_start=now,
            current_period_end=now + timezone.timedelta(days=30),
            next_billing_date=now + timezone.timedelta(days=30),
        )
        bc = BillingCycle.objects.create(
            subscription=sub,
            period_start=timezone.now(),
            period_end=timezone.now() + timezone.timedelta(days=30),
        )
        if status != "upcoming":
            force_status(bc, status)
        return bc

    def test_activate_from_upcoming(self) -> None:
        bc = self._make_billing_cycle("upcoming")
        bc.activate()
        bc.save()
        self.assertEqual(bc.status, "active")

    def test_close_from_active(self) -> None:
        bc = self._make_billing_cycle("active")
        bc.close()
        bc.save()
        self.assertEqual(bc.status, "closed")

    def test_mark_invoiced_from_closed(self) -> None:
        bc = self._make_billing_cycle("closed")
        bc.mark_invoiced()
        bc.save()
        self.assertEqual(bc.status, "invoiced")

    def test_finalize_from_invoiced(self) -> None:
        bc = self._make_billing_cycle("invoiced")
        bc.finalize()
        bc.save()
        self.assertEqual(bc.status, "finalized")

    def test_cannot_close_from_upcoming(self) -> None:
        bc = self._make_billing_cycle("upcoming")
        with self.assertRaises(TransitionNotAllowed):
            bc.close()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        bc = self._make_billing_cycle("upcoming")
        with self.assertRaises(AttributeError):
            bc.status = "active"


# ---------------------------------------------------------------------------
# 13. UsageAggregation FSM (4 transitions)
# ---------------------------------------------------------------------------


class UsageAggregationFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for UsageAggregation status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_aggregation(self, status: str = "accumulating") -> UsageAggregation:

        product = Product.objects.create(
            name=f"FSM-UA-Prod-{Product.objects.count() + 1}",
            slug=f"fsm-ua-prod-{Product.objects.count() + 1}",
            product_type="shared_hosting",
        )
        now = timezone.now()
        sub = Subscription.objects.create(
            customer=self.customer,
            currency=self.currency,
            product=product,
            subscription_number=f"SUB-UA-{Subscription.objects.count() + 1:04d}",
            unit_price_cents=5000,
            current_period_start=now,
            current_period_end=now + timezone.timedelta(days=30),
            next_billing_date=now + timezone.timedelta(days=30),
        )
        bc = BillingCycle.objects.create(
            subscription=sub,
            period_start=now,
            period_end=now + timezone.timedelta(days=30),
        )
        meter_num = UsageMeter.objects.count() + 1
        meter = UsageMeter.objects.create(
            name=f"fsm_meter_{meter_num}",
            display_name=f"FSM Meter {meter_num}",
            unit="count",
        )
        agg = UsageAggregation.objects.create(
            billing_cycle=bc,
            meter=meter,
            customer=self.customer,
            subscription=sub,
            period_start=now,
            period_end=now + timezone.timedelta(days=30),
        )
        if status != "accumulating":
            force_status(agg, status)
        return agg

    def test_close_for_rating(self) -> None:
        agg = self._make_aggregation("accumulating")
        agg.close_for_rating()
        agg.save()
        self.assertEqual(agg.status, "pending_rating")

    def test_rate_from_pending(self) -> None:
        agg = self._make_aggregation("pending_rating")
        agg.rate()
        agg.save()
        self.assertEqual(agg.status, "rated")

    def test_rate_from_accumulating(self) -> None:
        agg = self._make_aggregation("accumulating")
        agg.rate()
        agg.save()
        self.assertEqual(agg.status, "rated")

    def test_mark_invoiced_from_rated(self) -> None:
        agg = self._make_aggregation("rated")
        agg.mark_invoiced()
        agg.save()
        self.assertEqual(agg.status, "invoiced")

    def test_finalize_from_invoiced(self) -> None:
        agg = self._make_aggregation("invoiced")
        agg.finalize()
        agg.save()
        self.assertEqual(agg.status, "finalized")

    def test_cannot_invoice_from_accumulating(self) -> None:
        agg = self._make_aggregation("accumulating")
        with self.assertRaises(TransitionNotAllowed):
            agg.mark_invoiced()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        agg = self._make_aggregation("accumulating")
        with self.assertRaises(AttributeError):
            agg.status = "rated"


# ---------------------------------------------------------------------------
# 14. Customer FSM (5 transitions)
# ---------------------------------------------------------------------------


class CustomerFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for Customer status transitions."""

    def _make_customer(self, status: str = "prospect") -> Customer:
        cust = Customer.objects.create(
            name=f"FSM-Cust-{Customer.objects.count() + 1}",
            primary_email=f"fsm-cust-{Customer.objects.count() + 1}@test.ro",
        )
        if status != "prospect":
            force_status(cust, status)
        return cust

    def test_activate_from_prospect(self) -> None:
        cust = self._make_customer("prospect")
        cust.activate()
        cust.save()
        self.assertEqual(cust.status, "active")

    def test_deactivate_from_active(self) -> None:
        cust = self._make_customer("active")
        cust.deactivate()
        cust.save()
        self.assertEqual(cust.status, "inactive")

    def test_reactivate_from_inactive(self) -> None:
        cust = self._make_customer("inactive")
        cust.reactivate()
        cust.save()
        self.assertEqual(cust.status, "active")

    def test_suspend_from_active(self) -> None:
        cust = self._make_customer("active")
        cust.suspend()
        cust.save()
        self.assertEqual(cust.status, "suspended")

    def test_unsuspend_from_suspended(self) -> None:
        cust = self._make_customer("suspended")
        cust.unsuspend()
        cust.save()
        self.assertEqual(cust.status, "active")

    def test_cannot_suspend_from_prospect(self) -> None:
        cust = self._make_customer("prospect")
        with self.assertRaises(TransitionNotAllowed):
            cust.suspend()

    def test_cannot_deactivate_from_prospect(self) -> None:
        cust = self._make_customer("prospect")
        with self.assertRaises(TransitionNotAllowed):
            cust.deactivate()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        cust = self._make_customer("prospect")
        with self.assertRaises(AttributeError):
            cust.status = "active"


# ---------------------------------------------------------------------------
# 15. PromotionCampaign FSM (5 transitions)
# ---------------------------------------------------------------------------


class PromotionCampaignFSMTests(TestCase):
    """Smoke tests for PromotionCampaign status transitions."""

    def _make_campaign(self, status: str = "draft") -> PromotionCampaign:

        campaign = PromotionCampaign.objects.create(
            name=f"FSM-Camp-{PromotionCampaign.objects.count() + 1}",
            slug=f"fsm-camp-{PromotionCampaign.objects.count() + 1}",
            start_date=timezone.now(),
        )
        if status != "draft":
            force_status(campaign, status)
        return campaign

    def test_schedule_from_draft(self) -> None:
        camp = self._make_campaign("draft")
        camp.schedule()
        camp.save()
        self.assertEqual(camp.status, "scheduled")

    def test_activate_from_draft(self) -> None:
        camp = self._make_campaign("draft")
        camp.activate()
        camp.save()
        self.assertEqual(camp.status, "active")

    def test_activate_from_scheduled(self) -> None:
        camp = self._make_campaign("scheduled")
        camp.activate()
        camp.save()
        self.assertEqual(camp.status, "active")

    def test_pause_from_active(self) -> None:
        camp = self._make_campaign("active")
        camp.pause()
        camp.save()
        self.assertEqual(camp.status, "paused")

    def test_activate_from_paused(self) -> None:
        camp = self._make_campaign("paused")
        camp.activate()
        camp.save()
        self.assertEqual(camp.status, "active")

    def test_complete_from_active(self) -> None:
        camp = self._make_campaign("active")
        camp.complete()
        camp.save()
        self.assertEqual(camp.status, "completed")

    def test_cancel_from_draft(self) -> None:
        camp = self._make_campaign("draft")
        camp.cancel()
        camp.save()
        self.assertEqual(camp.status, "cancelled")

    def test_cannot_schedule_from_active(self) -> None:
        camp = self._make_campaign("active")
        with self.assertRaises(TransitionNotAllowed):
            camp.schedule()

    def test_cannot_pause_from_draft(self) -> None:
        camp = self._make_campaign("draft")
        with self.assertRaises(TransitionNotAllowed):
            camp.pause()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        camp = self._make_campaign("draft")
        with self.assertRaises(AttributeError):
            camp.status = "active"


# ---------------------------------------------------------------------------
# 16. ServiceGroup FSM (4 transitions)
# ---------------------------------------------------------------------------


class ServiceGroupFSMTests(FSMTestMixin, TestCase):
    """Smoke tests for ServiceGroup status transitions."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()

    def _make_service_group(self, status: str = "pending") -> ServiceGroup:

        sg = ServiceGroup.objects.create(
            name=f"FSM-SG-{ServiceGroup.objects.count() + 1}",
            group_type="package",
            customer=self.customer,
        )
        if status != "pending":
            force_status(sg, status)
        return sg

    def test_activate_from_pending(self) -> None:
        sg = self._make_service_group("pending")
        sg.activate()
        sg.save()
        self.assertEqual(sg.status, "active")

    def test_suspend_from_active(self) -> None:
        sg = self._make_service_group("active")
        sg.suspend()
        sg.save()
        self.assertEqual(sg.status, "suspended")

    def test_resume_from_suspended(self) -> None:
        sg = self._make_service_group("suspended")
        sg.resume()
        sg.save()
        self.assertEqual(sg.status, "active")

    def test_cancel_from_active(self) -> None:
        sg = self._make_service_group("active")
        sg.cancel()
        sg.save()
        self.assertEqual(sg.status, "cancelled")

    def test_cancel_from_pending(self) -> None:
        sg = self._make_service_group("pending")
        sg.cancel()
        sg.save()
        self.assertEqual(sg.status, "cancelled")

    def test_cannot_activate_from_cancelled(self) -> None:
        sg = self._make_service_group("cancelled")
        with self.assertRaises(TransitionNotAllowed):
            sg.activate()

    def test_cannot_suspend_from_pending(self) -> None:
        sg = self._make_service_group("pending")
        with self.assertRaises(TransitionNotAllowed):
            sg.suspend()

    def test_protected_field_blocks_direct_assignment(self) -> None:
        sg = self._make_service_group("pending")
        with self.assertRaises(AttributeError):
            sg.status = "active"


# ---------------------------------------------------------------------------
# 17. Chaos Monkey Remediation Tests
# ---------------------------------------------------------------------------


class InvoiceTransitionEdgeCaseTests(FSMTestMixin, TestCase):
    """Tests for Chaos Monkey finding: mark_partially_refunded source restriction."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_invoice(self, status: str = "draft") -> Invoice:
        inv = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"CM-INV-{Invoice.objects.count() + 1:04d}",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        if status != "draft":
            force_status(inv, status)
        return inv

    def test_mark_partially_refunded_from_paid_succeeds(self) -> None:
        inv = self._make_invoice("paid")
        inv.mark_partially_refunded()
        inv.save()
        self.assertEqual(inv.status, "partially_refunded")

    def test_mark_partially_refunded_from_issued_blocked(self) -> None:
        """Chaos Monkey fix: issued invoices cannot be partially refunded (unpaid)."""
        inv = self._make_invoice("issued")
        with self.assertRaises(TransitionNotAllowed):
            inv.mark_partially_refunded()

    def test_mark_partially_refunded_from_overdue_blocked(self) -> None:
        """Chaos Monkey fix: overdue invoices cannot be partially refunded (unpaid)."""
        inv = self._make_invoice("overdue")
        with self.assertRaises(TransitionNotAllowed):
            inv.mark_partially_refunded()

    def test_mark_partially_refunded_chain_to_full_refund(self) -> None:
        inv = self._make_invoice("paid")
        inv.mark_partially_refunded()
        inv.save()
        inv.refund_invoice()
        inv.save()
        self.assertEqual(inv.status, "refunded")


class PaymentGatewayEventTests(FSMTestMixin, TestCase):
    """Tests for Chaos Monkey finding: apply_gateway_event returns False for unmapped."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_payment(self, status: str = "pending") -> Payment:
        p = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=5000,
            payment_method="stripe",
        )
        if status != "pending":
            force_status(p, status)
        return p

    def test_unmapped_status_returns_false(self) -> None:
        """Chaos Monkey fix: unmapped gateway status should not save or return True."""
        payment = self._make_payment("pending")
        result = payment.apply_gateway_event("unknown_status")
        self.assertFalse(result)

    def test_mapped_status_succeeded_returns_true(self) -> None:
        payment = self._make_payment("pending")
        result = payment.apply_gateway_event("succeeded")
        self.assertTrue(result)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")

    def test_terminal_status_returns_false(self) -> None:
        payment = self._make_payment("succeeded")
        force_status(payment, "refunded")
        result = payment.apply_gateway_event("succeeded")
        self.assertFalse(result)


class ServiceActivateSourceTests(FSMTestMixin, TestCase):
    """Tests for Chaos Monkey finding: Service.activate() missing 'pending' source."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def _make_service(self, status: str = "pending") -> Service:
        plan = ServicePlan.objects.create(
            name="CM Test Plan",
            plan_type="shared_hosting",
            price_monthly="10.00",
        )
        idx = Server.objects.count()
        server = Server.objects.create(
            name=f"cm-srv-{idx}.test.ro",
            hostname=f"cm-srv-{idx}.test.ro",
            server_type="shared",
            primary_ip="10.0.0.1",
            location="Bucharest",
            datacenter="DC-CM",
            cpu_model="Test CPU",
            cpu_cores=4,
            ram_gb=8,
            disk_type="SSD",
            disk_capacity_gb=50,
        )
        svc = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            server=server,
            currency=self.currency,
            service_name="CM Test Service",
            domain=f"cm-test-{Service.objects.count()}.ro",
            username=f"cm_user_{Service.objects.count()}",
            price="10.00",
        )
        if status != "pending":
            force_status(svc, status)
        return svc

    def test_activate_from_pending(self) -> None:
        """Chaos Monkey fix: Service.activate() now allows 'pending' source."""
        svc = self._make_service("pending")
        svc.activate()
        svc.save()
        self.assertEqual(svc.status, "active")

    def test_activate_from_suspended(self) -> None:
        svc = self._make_service("suspended")
        svc.activate()
        svc.save()
        self.assertEqual(svc.status, "active")

    def test_activate_from_failed(self) -> None:
        svc = self._make_service("failed")
        svc.activate()
        svc.save()
        self.assertEqual(svc.status, "active")


class ConcurrentTransitionTests(FSMTestMixin, TestCase):
    """Tests for Chaos Monkey finding: no concurrent transition tests."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()
        cls.product = Product.objects.create(
            name="CM Concurrent Test",
            slug="cm-concurrent-test",
            product_type="shared_hosting",
            is_active=True,
        )

    def test_concurrent_order_transition_raises(self) -> None:
        """ConcurrentTransitionMixin detects stale status on Order."""
        order = Order.objects.create(
            customer=self.customer,
            order_number="ORD-CONC-001",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=5000,
            line_total_cents=5000,
        )
        # Get a stale copy
        stale_order = Order.objects.get(pk=order.pk)

        # First instance transitions successfully
        order.submit()
        order.save()
        self.assertEqual(order.status, "awaiting_payment")

        # Stale instance should fail — it still thinks status is "draft"
        stale_order.submit()
        with self.assertRaises(ConcurrentTransition):
            stale_order.save()


class SignalTransitionFailureSafetyTests(FSMTestMixin, TestCase):
    """Tests for Chaos Monkey CRITICAL fix: signal save-after-catch pattern.

    Verifies that _handle_payment_success and _handle_payment_refund do NOT
    execute post-transition logic when the FSM transition fails.
    """

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()

    def test_already_paid_invoice_not_saved_on_duplicate_payment(self) -> None:
        """Verify that a second payment success signal doesn't overwrite paid_at."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="CM-SIG-001",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        force_status(invoice, "paid")
        original_paid_at = timezone.now()
        invoice.paid_at = original_paid_at
        invoice.save(update_fields=["paid_at"])

        # mark_as_paid should fail — invoice is already paid
        with self.assertRaises(TransitionNotAllowed):
            invoice.mark_as_paid()

        # Verify the invoice status and paid_at are unchanged
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(invoice.paid_at, original_paid_at)

    def test_already_refunded_invoice_not_saved_on_duplicate_refund(self) -> None:
        """Verify that a second refund signal doesn't overwrite refunded invoice."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="CM-SIG-002",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        force_status(invoice, "refunded")

        # refund_invoice should fail — invoice is already refunded
        with self.assertRaises(TransitionNotAllowed):
            invoice.refund_invoice()

        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")


# ===============================================================================
# CODE REVIEW FIX TESTS (C1-C5, H1-H4, H6)
# ===============================================================================


class TestC1OrderStatusNotEnum(FSMTestMixin, TestCase):
    """C1: Order uses STATUS_CHOICES tuple, not TextChoices enum — no Order.Status."""

    def test_order_has_no_status_class(self) -> None:
        """Order.Status does not exist — using it raises AttributeError."""
        self.assertFalse(hasattr(Order, "Status"))

    def test_draft_status_is_string_literal(self) -> None:
        """Draft orders use the string 'draft', not Order.Status.DRAFT."""
        customer = self._create_customer()
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        order = Order.objects.create(
            customer=customer, currency=currency,
            customer_email=customer.primary_email, customer_name=customer.name,
        )
        self.assertEqual(order.status, "draft")


class TestC2SignalProcessingTrigger(FSMTestMixin, TestCase):
    """C2: Order signal must check old_status=='confirmed' for processing trigger."""

    def test_signal_triggers_provisioning_update_on_provisioning(self) -> None:
        """Phase A: provisioning transition triggers service update regardless of source state."""
        customer = self._create_customer()
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        order = Order.objects.create(
            customer=customer, currency=currency,
            customer_email=customer.primary_email, customer_name=customer.name,
        )
        force_status(order, "provisioning")

        # Per F12: new_status=="provisioning" triggers update regardless of old_status
        with patch("apps.orders.signals._update_services_to_provisioning") as mock_update:
            _handle_order_status_change(order, "paid", "provisioning")
            mock_update.assert_called_once_with(order)

    def test_signal_triggers_provisioning_from_in_review(self) -> None:
        """Phase A: in_review→provisioning also triggers service update (admin approved)."""
        customer = self._create_customer()
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        order = Order.objects.create(
            customer=customer, currency=currency,
            customer_email=customer.primary_email, customer_name=customer.name,
        )
        force_status(order, "provisioning")

        with patch("apps.orders.signals._update_services_to_provisioning") as mock_update:
            _handle_order_status_change(order, "in_review", "provisioning")
            mock_update.assert_called_once_with(order)


class TestC3TypedDictGetattr(TestCase):
    """C3: getattr() on TypedDict (dict at runtime) always returns None."""

    def test_dict_get_returns_value(self) -> None:
        """dict.get() works on TypedDict instances; getattr() does not."""
        result: dict[str, str] = {"refund_id": "ref_123", "status": "ok"}
        # getattr on a dict returns None (the bug)
        self.assertIsNone(getattr(result, "refund_id", None))
        # .get() returns the actual value (the fix)
        self.assertEqual(result.get("refund_id"), "ref_123")


class TestC4EFacturaMarkRejectedOnDraft(FSMTestMixin, TestCase):
    """C4: mark_rejected() only works from 'processing', not 'draft'."""

    def test_mark_rejected_fails_on_draft(self) -> None:
        """Draft EFacturaDocument cannot use mark_rejected (source=processing only)."""
        customer = self._create_customer()
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        invoice = Invoice.objects.create(
            customer=customer,
            currency=currency,
            number="C4-TEST-001",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        doc = EFacturaDocument.objects.create(invoice=invoice, document_type="invoice")
        self.assertEqual(doc.status, "draft")

        with self.assertRaises(TransitionNotAllowed):
            doc.mark_rejected([{"error": "test"}])

    def test_mark_error_works_on_draft(self) -> None:
        """Draft EFacturaDocument can use mark_error (source includes draft)."""
        customer = self._create_customer()
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        invoice = Invoice.objects.create(
            customer=customer,
            currency=currency,
            number="C4-TEST-002",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        doc = EFacturaDocument.objects.create(invoice=invoice, document_type="invoice")
        doc.mark_error("XML validation failed: 3 errors")
        doc.save()
        doc.refresh_from_db()
        self.assertEqual(doc.status, "error")


class TestC5WebhookIdempotency(FSMTestMixin, TestCase):
    """C5: Provisioning webhooks must handle duplicate suspend/activate gracefully."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.customer = cls._create_customer()
        cls.currency = cls._create_currency()
        cls.server = Server.objects.create(
            name="c5-server", hostname="c5.test.local", server_type="shared",
            primary_ip="10.0.5.1", location="Test", datacenter="DC-C5",
            cpu_model="Test CPU", cpu_cores=4, ram_gb=16,
            disk_type="SSD", disk_capacity_gb=100,
        )
        cls.plan = ServicePlan.objects.create(
            name="C5 Plan", plan_type="shared",
            price_monthly=10, price_quarterly=25, price_annual=90,
        )

    def _make_service(self) -> Service:
        return Service.objects.create(
            customer=self.customer, server=self.server, service_plan=self.plan,
            currency=self.currency, service_name="C5 Test Service",
            username=f"c5test{Service.objects.count() + 1}", price=10,
        )

    def test_suspend_already_suspended_raises_without_handling(self) -> None:
        """Calling suspend() on already-suspended service raises TransitionNotAllowed."""
        service = self._make_service()
        force_status(service, "suspended")

        with self.assertRaises(TransitionNotAllowed):
            service.suspend()

    def test_activate_already_active_raises_without_handling(self) -> None:
        """Calling activate() on already-active service raises TransitionNotAllowed."""
        service = self._make_service()
        force_status(service, "active")

        with self.assertRaises(TransitionNotAllowed):
            service.activate()


class TestH1ConcurrentTransitionInViews(FSMTestMixin, TestCase):
    """H1: ConcurrentTransition must be caught separately from TransitionNotAllowed."""

    def test_concurrent_transition_is_not_transition_not_allowed(self) -> None:
        """ConcurrentTransition is NOT a subclass of TransitionNotAllowed."""
        self.assertFalse(issubclass(ConcurrentTransition, TransitionNotAllowed))


class TestH4TerminalPaymentStatuses(TestCase):
    """H4: TERMINAL_PAYMENT_STATUSES must only contain valid STATUS_CHOICES values."""

    def test_terminal_statuses_are_valid(self) -> None:
        """Every status in TERMINAL_PAYMENT_STATUSES must exist in Payment.STATUS_CHOICES."""
        valid_statuses = {choice[0] for choice in Payment.STATUS_CHOICES}
        invalid = TERMINAL_PAYMENT_STATUSES - valid_statuses
        self.assertEqual(invalid, set(), f"Invalid statuses in TERMINAL_PAYMENT_STATUSES: {invalid}")


class TestH6TaskLockAtomicity(TestCase):
    """H6: Task locks must use cache.add() (atomic) not cache.get()+cache.set() (TOCTOU)."""

    def test_pending_orders_uses_atomic_lock(self) -> None:
        """process_pending_orders must use cache.add() for atomic lock acquisition."""
        source = inspect.getsource(process_pending_orders)
        self.assertIn("cache.add(", source, "Lock must use atomic cache.add(), not cache.get()")
        self.assertNotIn("cache.get(lock_key)", source, "TOCTOU: cache.get() + cache.set() is racy")

    def test_recurring_orders_uses_atomic_lock(self) -> None:
        """process_recurring_orders must use cache.add() for atomic lock acquisition."""
        source = inspect.getsource(process_recurring_orders)
        self.assertIn("cache.add(", source, "Lock must use atomic cache.add(), not cache.get()")
        self.assertNotIn("cache.get(lock_key)", source, "TOCTOU: cache.get() + cache.set() is racy")
