"""A domain bought through an order: priced from the TLD list, sent once, complete only when active.

The order line for a domain has no hosting service. Its price comes from the TLD price list before
totals and VAT, the registrar is asked once, and the line completes when the domain becomes active,
whichever path activates it. A registrar refusal fails the line: the customer reads a plain note and
staff are alerted with the reason.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from contextlib import nullcontext
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.db import transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory

from apps.api.orders.views import create_order, preflight_order
from apps.audit.models import AuditEvent
from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import Currency, Subscription
from apps.common.types import Retriability
from apps.domains.models import Domain, DomainOrderItem, TLDRegistrarAssignment
from apps.domains.order_fulfilment import fulfil_order_item_for_domain
from apps.domains.services import DomainOrderService, TLDService
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderCreateData, OrderService, StatusChangeData
from apps.orders.tasks import provision_order_item
from apps.products.models import Product, ProductPrice
from apps.provisioning.models import Service, ServicePlan
from tests.helpers.checkout import checkout_consents
from tests.orders.test_calculate_cart import _call_calculate

from .test_domain_service_logic import DomainFixtureMixin

REGISTER = "apps.domains.services.DomainRegistrarGateway.register_domain"
ALERT = "apps.notifications.services.NotificationService.send_admin_alert"


def _domain_line(product: Product, domain_name: str, unit_price_cents: int) -> dict[str, object]:
    return {
        "product_id": product.pk,
        "quantity": 1,
        "unit_price_cents": unit_price_cents,
        "billing_period": "once",
        "description": f"Domain name: {domain_name}",
        "domain_name": domain_name,
        "meta": {"domain_mode": "register"},
    }


class DomainOrderLineFixture(DomainFixtureMixin):
    def setUp(self) -> None:
        super().setUp()
        call_command("ensure_domain_product", stdout=StringIO())
        self.domain_product = Product.objects.get(product_type="domain")

    def _billing(self) -> dict[str, object]:
        return dict(OrderService.build_billing_address_from_customer(self.customer))

    def _create_order(self, *items: dict[str, object]) -> Order:
        result = OrderService.create_order(
            OrderCreateData(customer=self.customer, currency="RON", billing_address=self._billing(), items=list(items))
        )
        return result.unwrap()

    def _domain_order(self, domain_name: str = "flow.ro") -> tuple[Order, OrderItem]:
        price = DomainOrderService.quote_order_line(domain_name, "register", "RON").unwrap().total_cents
        order = self._create_order(_domain_line(self.domain_product, domain_name, price))
        Order.objects.filter(pk=order.pk).update(status="provisioning")
        order.refresh_from_db()
        return order, order.items.get()


class DomainOrderLineTests(DomainOrderLineFixture, TestCase):
    def test_cart_prices_a_domain_line_from_the_tld_list_for_its_shortest_period(self) -> None:
        currency = Currency.objects.get(code="RON")
        unit = TLDService.calculate_domain_cost(self.com_ro, 1, action="register", currency_code="RON")["total_cost_cents"]
        items = [
            {"product_id": self.domain_product.pk, "quantity": 1, "billing_period": "annual",
             "config": {"domain_mode": "register"}, "domain_name": "Two-Years.com.ro"},
            {"product_id": self.domain_product.pk, "quantity": 1, "billing_period": "annual",
             "config": {"domain_mode": "register"}, "domain_name": "nowhere.invalidtld"},
        ]

        data = _call_calculate(self.customer, currency, items)

        # .com.ro sells for at least two years; an extension nobody sells is a warning, not a line.
        self.assertEqual(data["subtotal_cents"], 2 * unit, data)
        self.assertEqual([line["domain_name"] for line in data["items"]], ["two-years.com.ro"])
        self.assertEqual([w["type"] for w in data["warnings"]], ["domain_unavailable"])

    def test_paid_mixed_order_enrolls_the_hosting_only_and_leaves_the_domain_to_its_registrar(self) -> None:
        plan = ServicePlan.objects.create(name="Basic", plan_type="shared_hosting", price_monthly=2999)
        hosting = Product.objects.create(
            slug="hosting", name="Hosting", product_type="shared_hosting", default_service_plan=plan
        )
        ProductPrice.objects.create(product=hosting, currency_id="RON", monthly_price_cents=2999, is_active=True)
        price = DomainOrderService.quote_order_line("mixed.ro", "register", "RON").unwrap().total_cents
        order = self._create_order(
            {"product_id": hosting.pk, "quantity": 1, "unit_price_cents": 2999, "billing_period": "monthly",
             "description": "Hosting"},
            _domain_line(self.domain_product, "mixed.ro", price),
        )
        domain_line = order.items.get(product=self.domain_product)
        hosting_line = order.items.get(product=hosting)
        recorded = domain_line.domain_order_item
        self.assertEqual(recorded.registrar, self.ro_registrar)
        self.assertTrue(
            AuditEvent.objects.filter(action="domain_order_created", object_id=str(recorded.pk)).exists()
        )

        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            for status in ("awaiting_payment", "paid", "provisioning"):
                result = OrderService.update_order_status(order, StatusChangeData(new_status=status))
                self.assertTrue(result.is_ok(), result)
                order.refresh_from_db()

        hosting_line.refresh_from_db()
        self.assertEqual(list(Service.objects.values_list("pk", flat=True)), [hosting_line.service_id])
        self.assertTrue(Subscription.objects.filter(service_id=hosting_line.service_id).exists())
        domain_line.refresh_from_db()
        self.assertEqual((domain_line.service_id, domain_line.provisioning_status), (None, "pending"))
        enqueued = [call.args for call in enqueue.call_args_list]
        self.assertIn(("apps.domains.tasks.process_order_domain_items", str(order.pk)), enqueued)
        self.assertNotIn(str(domain_line.pk), [str(arg) for args in enqueued for arg in args[1:]])
        # Hosting provisioning leaves a domain line alone even when asked for it directly.
        self.assertTrue(provision_order_item(str(domain_line.pk))["success"])
        domain_line.refresh_from_db()
        self.assertEqual(domain_line.provisioning_status, "pending")


    def _post(self, view: Callable[..., Response], item: dict[str, object]) -> Response:
        payload = {
            "currency": "RON",
            "currency_revision": get_selling_currency_policy().revision,
            "items": [item],
            **checkout_consents(),
        }
        request = APIRequestFactory().post(
            "/api/orders/test/", payload, format="json", HTTP_IDEMPOTENCY_KEY=uuid.uuid4().hex
        )
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            return view(request)

    def test_checkout_preflights_and_orders_a_domain_line_at_its_quote(self) -> None:
        quote = DomainOrderService.quote_order_line("api-order.ro", "register", "RON").unwrap()
        item = {
            "product_id": str(self.domain_product.pk),
            "quantity": 1,
            "billing_period": "annual",
            "config": {"domain_mode": "register", "product_price_id": "client-said-so"},
            "domain_name": "Api-Order.ro",
        }

        preflight = self._post(preflight_order, item)
        created = self._post(create_order, item)

        self.assertEqual(preflight.status_code, 200, preflight.data)
        self.assertEqual(created.status_code, 201, created.data)
        line = Order.objects.get(pk=created.data["order"]["id"]).items.get()
        self.assertEqual(line.unit_price_cents, quote.total_cents)
        # Only what the server derived reaches the line's config.
        self.assertEqual(
            (line.config["domain_mode"], line.config["billing_period"], "product_price_id" in line.config),
            ("register", "once", False),
        )
        recorded = line.domain_order_item
        self.assertEqual((recorded.domain_name, recorded.registrar), ("api-order.ro", self.ro_registrar))

    def test_an_order_whose_domain_cannot_be_recorded_or_is_mispriced_is_not_created(self) -> None:
        price = DomainOrderService.quote_order_line("lost.ro", "register", "RON").unwrap().total_cents
        orders = Order.objects.count()
        cases = {
            "not recorded": (price, patch.object(DomainOrderService, "create_domain_order_item", return_value=(False, ""))),
            "priced off its quote": (price - 1, nullcontext()),
        }
        for case, (unit_price_cents, failure) in cases.items():
            with self.subTest(case), failure:
                result = OrderService.create_order(
                    OrderCreateData(
                        customer=self.customer,
                        currency="RON",
                        billing_address=self._billing(),
                        items=[_domain_line(self.domain_product, "lost.ro", unit_price_cents)],
                    )
                )

                self.assertTrue(result.is_err())
                self.assertEqual(
                    (Order.objects.count(), OrderItem.objects.count(), DomainOrderItem.objects.count()),
                    (orders, 0, 0),
                )

    def test_an_order_cannot_await_payment_for_a_domain_no_longer_offered(self) -> None:
        price = DomainOrderService.quote_order_line("gone.ro", "register", "RON").unwrap().total_cents
        order = self._create_order(_domain_line(self.domain_product, "gone.ro", price))
        TLDRegistrarAssignment.objects.filter(tld=self.ro).update(is_active=False)

        result = OrderService.update_order_status(order, StatusChangeData(new_status="awaiting_payment"))

        self.assertTrue(result.is_err())
        self.assertIn("cannot be ordered right now", str(result.unwrap_err()))


class DomainOrderFulfilmentTests(DomainOrderLineFixture, TransactionTestCase):
    def _activate(self, domain: Domain) -> None:
        with transaction.atomic():
            locked = Domain.objects.select_for_update().get(pk=domain.pk)
            locked.expires_at = timezone.now() + timedelta(days=365)
            locked.activate()
            locked.save()

    def test_line_stays_in_progress_until_the_domain_activates_then_completes_once(self) -> None:
        order, line = self._domain_order()

        with patch(REGISTER, return_value=(True, {"pending": True, "operation_handle": "op-1"})) as register:
            DomainOrderService.process_domain_order_items(order)
            DomainOrderService.process_domain_order_items(order)

        register.assert_called_once()  # The claimed line is not sent again.
        line.refresh_from_db()
        domain = Domain.objects.get(name="flow.ro")
        self.assertEqual((line.provisioning_status, domain.status), ("in_progress", "pending"))
        self.assertEqual(line.domain_order_item.domain, domain)

        with self.assertRaises(RuntimeError), transaction.atomic():
            self._activate(domain)
            raise RuntimeError("activation rolled back")
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")

        self._activate(domain)

        line.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual((line.provisioning_status, order.status), ("completed", "completed"))
        self.assertEqual(fulfil_order_item_for_domain(domain.pk), 0)

    def test_cancelling_the_order_leaves_an_in_flight_registration_to_its_domain(self) -> None:
        order, line = self._domain_order()
        with patch(REGISTER, return_value=(True, {"pending": True, "operation_handle": "op-2"})):
            DomainOrderService.process_domain_order_items(order)

        result = OrderService.update_order_status(order, StatusChangeData(new_status="cancelled"))
        self.assertTrue(result.is_ok(), result)
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")

        self._activate(Domain.objects.get(name="flow.ro"))
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "completed")

    def test_an_immediate_registration_completes_the_line(self) -> None:
        order, line = self._domain_order()
        expiry = timezone.now() + timedelta(days=365)

        with patch(REGISTER, return_value=(True, {"registrar_domain_id": "flow", "expires_at": expiry})):
            processed = DomainOrderService.process_domain_order_items(order)

        line.refresh_from_db()
        self.assertEqual([domain.name for domain in processed], ["flow.ro"])
        self.assertEqual(line.provisioning_status, "completed")

    def test_an_unconfirmed_registration_keeps_the_line_waiting_and_tells_no_one(self) -> None:
        order, line = self._domain_order()
        unknown = (False, {"error": "registrar timed out", "retriability": Retriability.UNKNOWN.value})

        with patch(REGISTER, return_value=unknown), patch(ALERT) as alert:
            DomainOrderService.process_domain_order_items(order)

        # The registrar may still register it: failing the line would send staff to register it twice.
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")
        self.assertEqual(Domain.objects.get(name="flow.ro").status, "pending")
        alert.assert_not_called()

    def test_a_crash_before_the_registrar_is_asked_fails_the_line_for_staff(self) -> None:
        order, line = self._domain_order()
        crash = patch(
            "apps.domains.services.DomainLifecycleService._build_registrant_data", side_effect=RuntimeError("db down")
        )

        with crash, patch(REGISTER) as register, patch(ALERT) as alert:
            DomainOrderService.process_domain_order_items(order)

        register.assert_not_called()
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "failed")
        self.assertIn("db down", alert.call_args.kwargs["message"])

    @override_settings(REGISTRAR_ADAPTERS_VERIFIED=False)
    def test_unverified_adapter_refusal_fails_the_line_and_alerts_staff(self) -> None:
        order, line = self._domain_order()

        with patch(ALERT) as alert:
            DomainOrderService.process_domain_order_items(order)

        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "failed")
        self.assertFalse(Domain.objects.filter(name="flow.ro").exists())
        self.assertIsNone(DomainOrderItem.objects.get(order_item=line).domain_id)
        # The customer's note is plain; the registrar's reason goes to staff only.
        self.assertNotIn("verified", line.provisioning_notes)
        alert.assert_called_once()
        self.assertIn("flow.ro", alert.call_args.kwargs["subject"])
        self.assertIn("not verified", alert.call_args.kwargs["message"])

    def test_a_line_whose_order_is_not_being_provisioned_is_not_sent(self) -> None:
        order, line = self._domain_order()
        Order.objects.filter(pk=order.pk).update(status="cancelled")

        with patch(REGISTER) as register:
            DomainOrderService.process_domain_order_items(order)

        register.assert_not_called()
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "pending")


class EnsureDomainProductTests(TestCase):
    def test_creates_one_domain_product_and_keeps_an_existing_one(self) -> None:
        existing = Product.objects.create(slug="domains", name="Domains", product_type="domain")

        for _run in range(2):
            call_command("ensure_domain_product", stdout=StringIO())

        self.assertEqual(list(Product.objects.filter(product_type="domain")), [existing])
        existing.delete()
        call_command("ensure_domain_product", stdout=StringIO())
        self.assertEqual(list(Product.objects.filter(product_type="domain").values_list("slug", flat=True)), ["domain"])
