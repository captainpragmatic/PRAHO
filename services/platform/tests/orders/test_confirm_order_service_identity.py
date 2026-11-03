"""Signed checkout confirmation has one Service owner: the order line (#839)."""

from decimal import Decimal
from unittest import skipUnless
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection
from django.http import HttpResponse
from django.test import TestCase, TransactionTestCase, override_settings

from apps.billing.gateways.base import PaymentConfirmResult
from apps.billing.models import Invoice, InvoiceSequence, Payment
from apps.billing.payment_convergence import PaymentSuccessService
from apps.billing.payment_service import PaymentService
from apps.billing.proforma_service import ProformaPaymentService
from apps.billing.subscription_models import Subscription
from apps.orders.models import Order
from apps.orders.services import OrderCreateData, OrderService, StatusChangeData
from apps.products.models import ProductPrice
from apps.provisioning.models import Service
from apps.users.models import CustomerMembership, User
from tests.domains.test_domain_order_flow import DomainOrderLineFixture, _domain_line
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin
from tests.helpers.task_queue import quiet_task_queue
from tests.orders._hosting_workflow_case import HostingWorkflowCase
from tests.provisioning.test_virtualmin_credentials import create_test_server


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class ConfirmOrderServiceIdentityTests(BoundSessionMixin, HMACTestMixin, HostingWorkflowCase):
    def setUp(self) -> None:
        self.broker = quiet_task_queue(self)
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.owner = User.objects.create_user(email="confirmation-839-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        # An active generic server makes the current extra writer actually create its Service.
        # No worker consumes the captured broker packages and no native call is made.
        create_test_server(management_api_url="")

    def prepare_payment(self, order: Order) -> Payment:
        self.assertEqual(order.status, "awaiting_payment")
        # TransactionTestCase flushes data-migration seeds between classes.
        InvoiceSequence.objects.get_or_create(scope="default", defaults={"prefix": "INV"})
        InvoiceSequence.objects.get_or_create(scope="subscription", defaults={"prefix": "SUB"})
        intent = f"pi_identity839{order.pk.hex}"
        order.payment_intent_id = intent
        order.payment_method = "card"
        order.save(update_fields=["payment_intent_id", "payment_method"])
        payment = Payment.objects.create(
            customer=self.customer, currency=order.currency, amount_cents=order.total_cents,
            payment_method="stripe", gateway_txn_id=intent, proforma=order.proforma,
            meta={"proforma_id": str(order.proforma_id)},
        )
        self.assertIsNone(payment.invoice_id)
        return payment

    def request_confirmation(self, order: Order, *, billing_first: bool = False) -> HttpResponse:
        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.confirm_payment.return_value = PaymentConfirmResult(
                success=True, status="succeeded", error=None, amount_received=order.total_cents, currency="ron",
            )
            if billing_first:
                settled = PaymentService.confirm_payment(order.payment_intent_id, customer_id=self.customer.pk)
                self.assertTrue(settled["success"], settled)
                # The Portal's billing pre-step has settled the payment, but the
                # webhook has not converted its proforma. This is the real race.
                self.assertIsNone(Payment.objects.get(gateway_txn_id=order.payment_intent_id).invoice_id)
            return self.portal_post(f"/api/orders/{order.pk}/confirm/", {
                "customer_id": self.customer.pk, "user_id": self.owner.pk,
                "payment_intent_id": order.payment_intent_id,
            })

    def assert_confirmed(self, order: Order, payment: Payment, response: HttpResponse, service_ids: set[int]) -> None:
        self.assertEqual(response.status_code, 200, response.content)
        order.refresh_from_db()
        self.assertEqual(order.status, "provisioning")
        self.assertEqual(Invoice.objects.filter(converted_from_proforma=order.proforma).count(), 1)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertIsNotNone(order.invoice_id)
        self.assertEqual(payment.invoice_id, order.invoice_id)
        self.assertSetEqual(
            set(Service.objects.filter(customer=self.customer).values_list("pk", flat=True)),
            service_ids,
            f"Confirmation created an unlinked Service; queued jobs: {self.broker.queued()}",
        )
        self.assertSetEqual(set(order.items.values_list("service_id", flat=True)), service_ids)
        self.assertCountEqual(
            [job[1] for job in self.broker.queued() if job[0] == "apps.orders.tasks.provision_order_item"],
            [str(pk) for pk in order.items.values_list("pk", flat=True)],
        )
        self.assertFalse(any(job[0] == "apps.provisioning.tasks.provision_service_task" for job in self.broker.queued()))
        self.assertEqual(Subscription.objects.filter(service_id__in=service_ids).count(), len(service_ids))

    def test_delayed_webhook_confirmation_preserves_the_only_linked_service(self) -> None:
        order = self.create_order()
        original_id = order.items.get().service_id
        self.assertIsNotNone(original_id)
        self.assertEqual(list(Service.objects.values_list("pk", flat=True)), [original_id])
        payment = self.prepare_payment(order)
        self.assertIsNone(order.invoice_id)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request_confirmation(order)
        self.assert_confirmed(order, payment, response, {original_id})
        self.assertEqual(response.json()["provisioning"], [])

    def test_portal_billing_prestep_and_replay_preserve_identity_and_enrollment(self) -> None:
        order = self.create_order()
        original_id = order.items.get().service_id
        payment = self.prepare_payment(order)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request_confirmation(order, billing_first=True)
            replay = self.request_confirmation(order)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assert_confirmed(order, payment, response, {original_id})
        subscription = Subscription.objects.get(service_id=original_id)
        self.assertEqual((subscription.unit_price_cents, subscription.currency_id), (10000, "RON"))

    def test_missing_service_is_created_and_bound_only_by_canonical_confirmation(self) -> None:
        order = self.create_order()
        service = order.items.get().service
        order.items.update(service=None)
        service.delete()
        self.assertFalse(Service.objects.exists())
        payment = self.prepare_payment(order)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request_confirmation(order)
        line = order.items.get()
        self.assertIsNotNone(line.service_id)
        self.assert_confirmed(order, payment, response, {line.service_id})

    def test_annual_multiple_manual_lines_keep_purchased_periods_and_prices(self) -> None:
        ProductPrice.objects.filter(product=self.product).update(annual_discount_percent=Decimal("25.00"))
        self.assertEqual(ProductPrice.objects.get(product=self.product).get_price_for_period("annual"), Decimal("900"))
        items = [{
            "product_id": self.product.pk, "quantity": 1, "unit_price_cents": 90000,
            "setup_cents": 0, "billing_period": "annual", "domain_name": f"annual-{i}.example.test",
            "description": self.product.name,
        } for i in range(2)]
        order = self.create_order(items=items)
        original_ids = set(order.items.values_list("service_id", flat=True))
        self.assertEqual(len(original_ids), 2)
        self.assertFalse(self.plan.auto_provision)
        payment = self.prepare_payment(order)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request_confirmation(order, billing_first=True)
        self.assert_confirmed(order, payment, response, original_ids)
        self.assertEqual(list(Service.objects.values_list("billing_cycle", "price")),
                         [("annual", Decimal("900.00"))] * 2)
        self.assertEqual(list(Subscription.objects.values_list("billing_cycle", "unit_price_cents")),
                         [("yearly", 90000)] * 2)

    def test_no_generic_server_still_confirms_the_linked_service(self) -> None:
        from apps.provisioning.models import Server  # noqa: PLC0415

        Server.objects.all().delete()
        order = self.create_order()
        original_id = order.items.get().service_id
        payment = self.prepare_payment(order)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request_confirmation(order)
        self.assert_confirmed(order, payment, response, {original_id})
        self.assertEqual(response.json()["provisioning"], [])

    def test_webhook_first_confirmation_and_replay_queue_no_second_dispatch(self) -> None:
        order = self.create_order()
        original_id = order.items.get().service_id
        payment = self.prepare_payment(order)
        with self.captureOnCommitCallbacks(execute=True):
            payment = PaymentSuccessService.converge_gateway_success(
                order.payment_intent_id, {"amount_received": order.total_cents, "currency": "ron"},
            ).unwrap()
            ProformaPaymentService.record_payment_and_convert(
                str(order.proforma_id), order.total_cents, "stripe", existing_payment=payment,
            ).unwrap()
        jobs = list(self.broker.queued())
        response = self.request_confirmation(order)
        replay = self.request_confirmation(order)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assert_confirmed(order, payment, response, {original_id})
        self.assertEqual(self.broker.queued(), jobs)


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL commit ordering")
@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class ConfirmOrderCommitIdentityTests(BoundSessionMixin, HMACTestMixin, TransactionTestCase):
    """No test-wide transaction: Phase 3 callbacks run before the API returns."""

    prepare_payment = ConfirmOrderServiceIdentityTests.prepare_payment
    request_confirmation = ConfirmOrderServiceIdentityTests.request_confirmation
    assert_confirmed = ConfirmOrderServiceIdentityTests.assert_confirmed

    def test_real_commit_preserves_linkage_payment_and_canonical_dispatch(self) -> None:
        self.broker = quiet_task_queue(self)
        HostingWorkflowCase.setUp(self)
        cache.clear()
        self.addCleanup(cache.clear)
        self.owner = User.objects.create_user(email="commit-839@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        create_test_server(management_api_url="")
        self.assertFalse(connection.in_atomic_block)
        with connection.cursor() as cursor:
            cursor.execute("SHOW transaction_isolation")
            self.assertEqual(cursor.fetchone()[0], "read committed")
        order = OrderService.create_order(OrderCreateData(
            customer=self.customer, billing_address=self.address,
            items=[{"product_id": self.product.pk, "quantity": 1, "unit_price_cents": 10000,
                    "billing_period": "monthly", "setup_cents": 0, "description": self.product.name}],
        ), created_by=self.admin).unwrap()
        OrderService.update_order_status(order, StatusChangeData(new_status="awaiting_payment")).unwrap()
        order.refresh_from_db()
        service_id = order.items.get().service_id
        self.assertIsNotNone(service_id)
        payment = self.prepare_payment(order)
        response = self.request_confirmation(order, billing_first=True)
        self.assertFalse(connection.in_atomic_block)
        self.assert_confirmed(order, payment, response, {service_id})


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class ConfirmMixedOrderIdentityTests(BoundSessionMixin, HMACTestMixin, DomainOrderLineFixture, TestCase):
    prepare_payment = ConfirmOrderServiceIdentityTests.prepare_payment
    request_confirmation = ConfirmOrderServiceIdentityTests.request_confirmation

    def test_confirmation_keeps_domain_work_with_its_registrar_and_hosting_with_its_service(self) -> None:
        from apps.domains.services import DomainOrderService  # noqa: PLC0415
        from apps.products.models import Product  # noqa: PLC0415
        from apps.provisioning.models import ServicePlan  # noqa: PLC0415

        broker = quiet_task_queue(self)
        cache.clear()
        self.addCleanup(cache.clear)
        self.owner = User.objects.create_user(email="mixed-839@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        create_test_server(management_api_url="")
        plan = ServicePlan.objects.create(name="Mixed hosting", plan_type="shared_hosting", price_monthly=100)
        hosting = Product.objects.create(slug="mixed-839", name="Mixed hosting", product_type="shared_hosting",
                                         default_service_plan=plan)
        ProductPrice.objects.create(product=hosting, currency_id="RON", monthly_price_cents=10000)
        price = DomainOrderService.quote_order_line("mixed839.ro", "register", "RON").unwrap().total_cents
        with self.captureOnCommitCallbacks(execute=True):
            order = self._create_order(
                {"product_id": hosting.pk, "quantity": 1, "unit_price_cents": 10000,
                 "billing_period": "monthly", "description": hosting.name},
                _domain_line(self.domain_product, "mixed839.ro", price),
            )
            OrderService.update_order_status(order, StatusChangeData(new_status="awaiting_payment")).unwrap()
        order.refresh_from_db()
        service_id = order.items.get(product=hosting).service_id
        self.assertIsNotNone(service_id)
        domain_line = order.items.get(product=self.domain_product)
        registrar_id = domain_line.domain_order_item.registrar_id
        self.prepare_payment(order)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request_confirmation(order, billing_first=True)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(list(Service.objects.values_list("pk", flat=True)), [service_id])
        domain_line.refresh_from_db()
        self.assertEqual((domain_line.service_id, domain_line.provisioning_status), (None, "pending"))
        self.assertEqual(domain_line.domain_order_item.registrar_id, registrar_id)
        self.assertEqual(Subscription.objects.get().service_id, service_id)
        self.assertIn(("apps.domains.tasks.process_order_domain_items", str(order.pk)), broker.queued())
        self.assertNotIn(("apps.orders.tasks.provision_order_item", str(domain_line.pk)), broker.queued())
        self.assertFalse(any(job[0] == "apps.provisioning.tasks.provision_service_task" for job in broker.queued()))
