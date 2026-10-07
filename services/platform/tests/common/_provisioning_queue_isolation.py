"""Shared real ORM enqueue failures for provisioning signal regressions."""

from collections.abc import Callable
from decimal import Decimal
from unittest.mock import patch

from django.db import connection, transaction
from django.test import TestCase
from django_q.models import OrmQ

from apps.billing.models import Currency, Invoice
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from tests.helpers.fsm_helpers import force_status

_FAILED_ENQUEUE = 2


class ProvisioningQueueIsolationTestCase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        OrmQ.objects.all().delete()
        with patch("django_q.tasks.async_task", return_value="fixture-job"):
            currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
            Currency.objects.get_or_create(code="XTS", defaults={"symbol": "test"})
            customer = Customer.objects.create(name="Queue isolation", primary_email="queue@example.com")
            self.invoice = Invoice.objects.create(customer=customer, currency=currency, number="QUEUE-ISOLATION")
            self.order = Order.objects.create(
                customer=customer,
                currency=currency,
                invoice=self.invoice,
                customer_email=customer.primary_email,
                customer_name=customer.name,
            )
            product = Product.objects.create(name="Hosting", slug="queue-hosting", product_type="shared_hosting")
            plan = ServicePlan.objects.create(name="Hosting", plan_type="shared_hosting", price_monthly=Decimal("10"))
            self.services: list[Service] = []
            self.items: list[OrderItem] = []
            for index in range(3):
                service = Service.objects.create(
                    customer=customer,
                    currency=currency,
                    service_plan=plan,
                    service_name=f"queue-{index}",
                    username=f"queue-{index}",
                    domain=f"queue-{index}.example.com",
                    price=Decimal("10"),
                )
                force_status(service, "active")
                self.services.append(service)
                self.items.append(
                    OrderItem.objects.create(
                        order=self.order,
                        product=product,
                        service=service,
                        product_name=product.name,
                        product_type=product.product_type,
                        unit_price_cents=1000,
                    )
                )

    def assert_jobs_survive(
        self, trigger: Callable[[], None], *, function: str, expected_args: list[tuple[object, ...]]
    ) -> None:
        attempts = 0

        def fail_second_enqueue(
            execute: Callable[..., object], sql: str, params: object, many: bool, context: dict[str, object]
        ) -> object:
            nonlocal attempts
            if sql.startswith(f'INSERT INTO "{OrmQ._meta.db_table}"'):
                attempts += 1
                if attempts == _FAILED_ENQUEUE:
                    # save_base marks the caller transaction as needing rollback.
                    Currency.objects.create(code="XTS", symbol="duplicate")
            return execute(sql, params, many, context)

        with (
            patch("django_q.conf.Conf.SYNC", False),
            connection.execute_wrapper(fail_second_enqueue),
            transaction.atomic(),
        ):
            trigger()
            self.assertFalse(connection.needs_rollback)
        jobs = list(OrmQ.objects.order_by("pk"))
        self.assertEqual(len(jobs), 2, "The first enqueue must survive and the third must still run")
        self.assertEqual([job.func() for job in jobs], [function, function])
        self.assertEqual([job.args() for job in jobs], expected_args)
        self.assertEqual(attempts, 3)
        self.assertEqual(Currency.objects.filter(code="XTS").count(), 1)
