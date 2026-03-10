"""
FSM transition smoke tests for all 10 django-fsm-2 protected models.

Verifies that:
1. Every @transition method succeeds from its declared source state(s)
2. Invalid transitions raise TransitionNotAllowed
3. FSMField(protected=True) blocks direct .status = assignment

Part of the defense-in-depth strategy from ADR-0034.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.billing.currency_models import Currency
from apps.billing.invoice_models import Invoice
from apps.billing.payment_models import Payment
from apps.billing.proforma_models import ProformaInvoice
from apps.billing.refund_models import Refund
from apps.billing.subscription_models import Subscription
from apps.customers.customer_models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
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
