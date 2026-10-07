"""Payment provisioning dispatches must carry their configured worker budget."""

from __future__ import annotations

from decimal import Decimal
from typing import cast

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.billing.signals import _trigger_virtualmin_provisioning_on_payment
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.settings.services import SettingsService
from tests.factories.billing_factories import CurrencyFactory, CustomerFactory, InvoiceFactory

TASK_BUDGET_KEY = "provisioning.task_time_limit"
PROVISION_TASK = "apps.provisioning.virtualmin_tasks.provision_virtualmin_account"


class PaymentProvisioningBudgetTests(TestCase):
    def test_payment_dispatch_serializes_current_budget_for_every_hosting_service(self) -> None:
        customer = CustomerFactory()
        currency = CurrencyFactory()
        invoice = InvoiceFactory(customer=customer, currency=currency, bill_to_country="DE")
        plan = ServicePlan.objects.create(
            name="Payment budget plan", plan_type="shared_hosting", price_monthly=Decimal("10")
        )
        product = Product.objects.create(
            name="Payment budget hosting", slug="payment-budget-hosting", product_type="shared_hosting"
        )
        order = Order.objects.create(customer=customer, currency=currency, invoice=invoice)
        services: list[Service] = []
        for index in range(3):
            service = Service.objects.create(
                customer=customer,
                currency=currency,
                service_plan=plan,
                service_name=f"payment-budget-{index}.example.test",
                domain=f"payment-budget-{index}.example.test",
                username=f"paymentbudget{index}",
                billing_cycle="monthly",
                price=Decimal("10"),
                status="active",
            )
            services.append(service)
            OrderItem.objects.create(order=order, product=product, service=service, unit_price_cents=1000)

        for budget in (720, 960):
            with self.subTest(budget=budget):
                result = SettingsService.update_setting(TASK_BUDGET_KEY, budget)
                self.assertTrue(result.is_ok(), str(result))
                previous_rows = list(OrmQ.objects.values_list("pk", flat=True))
                with CaptureQueriesContext(connection) as queries:
                    _trigger_virtualmin_provisioning_on_payment(invoice)
                tasks = [
                    cast("dict[str, object]", SignedPackage.loads(row.payload))
                    for row in OrmQ.objects.exclude(pk__in=previous_rows).order_by("pk")
                ]
                self.assertEqual(len(tasks), 3)
                self.assertEqual([task.get("timeout") for task in tasks], [budget] * 3)
                self.assertEqual([task["func"] for task in tasks], [PROVISION_TASK] * 3)
                self.assertEqual([task["kwargs"] for task in tasks], [{}] * 3)
                self.assertCountEqual(
                    [task["args"] for task in tasks],
                    [
                        ({"service_id": str(service.pk), "domain": service.domain, "template": "Default"},)
                        for service in services
                    ],
                )
                setting_reads = [
                    query
                    for query in queries
                    if query["sql"].lstrip().upper().startswith("SELECT")
                    and '"setting_entries"' in query["sql"]
                    and TASK_BUDGET_KEY in query["sql"]
                ]
                self.assertEqual(len(setting_reads), 1)
