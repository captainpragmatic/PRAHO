"""Paid orders enter service enrollment; unpaid orders cannot provision."""

import pytest

from apps.billing.subscription_models import Subscription
from apps.orders.models import OrderStatusHistory
from apps.orders.services import OrderService, OrderServiceCreationService, StatusChangeData
from apps.products.models import Product, ProductPrice
from apps.provisioning.models import Service
from apps.provisioning.services import ProvisioningService
from tests.e2e.orm.workflow import WorkflowCase

pytestmark = pytest.mark.e2e


class TestServiceProvisioningWorkflow(WorkflowCase):
    def test_order_to_provisioning_flow(self):
        order = self.create_order()
        self.assertTrue(OrderServiceCreationService.update_service_status_on_payment(order).is_err())
        self.assertFalse(Subscription.objects.exists())
        self.pay(order)
        service = order.items.get().service
        self.assertIsNotNone(service)
        self.assertEqual((service.customer_id, service.status), (self.customer.pk, "provisioning"))
        self.assertEqual(service.service_plan_id, self.plan.pk)
        self.assertEqual(Subscription.objects.get(service=service).unit_price_cents, 10000)
        self.pay(order)
        self.assertEqual(Service.objects.count(), 1)
        self.assertEqual(Subscription.objects.count(), 1)

    def test_hosting_product_provisioning_requirements(self):
        self.product.requires_domain = True
        self.product.domain_required_at_signup = True
        self.product.save(update_fields=["requires_domain", "domain_required_at_signup"])
        order = self.create_order(submit=False)
        result = OrderService.update_order_status(order, StatusChangeData(new_status="awaiting_payment"))
        self.assertTrue(result.is_err())
        order.refresh_from_db()
        self.assertEqual(order.status, "draft")
        self.assertIsNone(order.proforma_id)
        self.assertFalse(Service.objects.exists())

    def test_order_with_multiple_services(self):
        second = Product.objects.create(
            name="Second Hosting",
            slug="second-hosting",
            requires_domain=False,
            product_type="shared_hosting",
            default_service_plan=self.plan,
        )
        ProductPrice.objects.create(product=second, currency=self.currency, monthly_price_cents=10000)
        order = self.create_order(
            items=[
                {
                    "product_id": product.pk,
                    "quantity": 1,
                    "unit_price_cents": 10000,
                    "billing_period": "monthly",
                    "description": product.name,
                }
                for product in (self.product, second)
            ]
        )
        self.pay(order)
        self.assertEqual(order.total_cents, 24200)
        services = list(order.items.values_list("service_id", flat=True))
        self.assertEqual(len(set(services)), 2)
        self.assertNotIn(None, services)
        self.assertEqual(Subscription.objects.filter(service_id__in=services).count(), 2)


class TestProvisioningStatusWorkflow(WorkflowCase):
    def test_order_status_workflow(self):
        order = self.create_order()
        self.pay(order)
        item = order.items.get()
        # Staff-completed manual provisioning, followed by the real completion signal.
        self.assertTrue(ProvisioningService.activate_service(item.service).is_ok())
        with self.captureOnCommitCallbacks(execute=True):
            item.start_provisioning()
            item.save()
            item.complete_provisioning()
            item.save()
        order.refresh_from_db()
        self.assertEqual(order.status, "completed")
        self.assertIsNotNone(order.completed_at)
        states = list(
            OrderStatusHistory.objects.filter(order=order).order_by("created_at").values_list("new_status", flat=True)
        )
        self.assertEqual(states, ["draft", "awaiting_payment", "paid", "provisioning", "completed"])


class TestProvisioningWithDomain(WorkflowCase):
    def test_hosting_order_retains_requested_domain(self):
        self.product.requires_domain = True
        self.product.domain_required_at_signup = True
        self.product.save(update_fields=["requires_domain", "domain_required_at_signup"])
        order = self.create_order(
            items=[
                {
                    "product_id": self.product.pk,
                    "quantity": 1,
                    "unit_price_cents": 10000,
                    "billing_period": "monthly",
                    "description": self.product.name,
                    "domain_name": "workflow.example",
                }
            ]
        )
        self.pay(order)
        item = order.items.get()
        self.assertEqual(item.domain_name, "workflow.example")
        self.assertEqual(item.service.domain, "workflow.example")
        self.assertEqual(item.service.status, "provisioning")


class TestBundleProvisioning(WorkflowCase):
    def test_order_retains_bundle_configuration(self):
        components = [
            {"type": "hosting", "plan": "standard"},
            {"type": "domain", "name": "bundle.example"},
            {"type": "ssl", "plan": "standard"},
        ]
        order = self.create_order(
            items=[
                {
                    "product_id": self.product.pk,
                    "quantity": 1,
                    "unit_price_cents": 14900,
                    "billing_period": "monthly",
                    "description": "Hosting bundle",
                    "domain_name": "bundle.example",
                    "meta": {"bundle_components": components},
                }
            ]
        )
        invoice = self.pay(order)
        item = order.items.get()
        self.assertEqual(item.config["bundle_components"], components)
        self.assertEqual(item.service.domain, "bundle.example")
        self.assertEqual(invoice.total_cents, 18029)
        self.assertEqual(Subscription.objects.get(service=item.service).unit_price_cents, 14900)
