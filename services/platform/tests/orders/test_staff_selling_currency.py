"""Staff creation must confirm the current selling policy and use its explicit prices."""

from decimal import Decimal
from html.parser import HTMLParser

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.billing.currency_policy import get_selling_currency_policy
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.products.models import Product, ProductPrice
from apps.provisioning.service_models import Service, ServicePlan, ServicePlanPrice
from apps.settings.services import SettingsService
from apps.users.models import User


class FormControlOwners(HTMLParser):
    """Resolve native HTML form ownership, including controls outside the form element."""

    def __init__(self) -> None:
        super().__init__()
        self.current_form = None
        self.owners = {}

    def handle_starttag(self, tag, attrs) -> None:
        values = dict(attrs)
        if tag == "form":
            self.current_form = values.get("id") or "anonymous-form"
        elif tag in {"input", "select", "textarea"} and values.get("name"):
            self.owners[values["name"]] = values.get("form", self.current_form)

    def handle_endtag(self, tag) -> None:
        if tag == "form":
            self.current_form = None


class StaffSellingCurrencyTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user("staff-currency@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(self.staff)
        self.customer = Customer.objects.create(name="Staff currency customer", primary_email="customer@example.test")
        self.product = Product.objects.create(name="Staff hosting", slug="staff-currency-hosting", product_type="hosting")
        self.plan = ServicePlan.objects.create(name="Staff service plan", price_monthly=Decimal("50.00"))
        for code, cents in (("RON", 5000), ("EUR", 1000), ("USD", 1200)):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            ProductPrice.objects.create(product=self.product, currency_id=code, monthly_price_cents=cents)
            ServicePlanPrice.objects.update_or_create(
                service_plan=self.plan, currency_id=code, defaults={"monthly_price_cents": cents},
            )
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code, quote_code_id="RON", rate=Decimal("4.97"), as_of=timezone.localdate(),
                    source=FXRate.Source.BNR, source_reference="staff-currency-test", fetched_at=timezone.now(),
                )

    def switch(self, code: str):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", code), Ok)
        return get_selling_currency_policy()

    def order_payload(self, code: str, revision: int) -> dict:
        return {
            "customer": self.customer.pk, "currency": code, "currency_revision": revision,
            "payment_method": "bank_transfer", "first_product": self.product.pk,
            "first_billing_period": "monthly", "first_quantity": 1,
        }

    def test_create_forms_show_fixed_currency_and_policy_revision(self) -> None:
        policy = self.switch("EUR")
        for url in ("orders:order_create", "provisioning:service_create"):
            with self.subTest(url=url):
                response = self.client.get(reverse(url))
                self.assertContains(response, 'name="currency_revision"')
                self.assertContains(response, f'value="{policy.revision}"')
                self.assertContains(response, "EUR")
                self.assertNotContains(response, '<select id="id_currency"')

    def test_initial_product_fields_are_submitted_by_the_create_order_form(self) -> None:
        response = self.client.get(reverse("orders:order_create"))
        controls = FormControlOwners()
        controls.feed(response.content.decode())
        owner = controls.owners["currency_revision"]
        self.assertIsNotNone(owner)
        item_fields = {"first_product", "first_billing_period", "first_quantity", "first_domain_name"}
        submitted = {name for name in item_fields if controls.owners.get(name) == owner}
        self.assertEqual(submitted, item_fields)

    def test_staff_orders_use_each_current_currency_and_product_price(self) -> None:
        for code, cents in (("RON", 5000), ("EUR", 1000), ("USD", 1200)):
            policy = self.switch(code)
            response = self.client.post(
                reverse("orders:order_create_with_item"), self.order_payload(code, policy.revision),
            )
            self.assertEqual(response.status_code, 302)
            order = Order.objects.get(currency_id=code)
            self.assertEqual(order.items.get().unit_price_cents, cents)
            self.assertEqual(order.subtotal_cents, cents)

    def test_staff_order_and_preview_reject_stale_currency_and_revision(self) -> None:
        old = get_selling_currency_policy()
        self.switch("EUR")
        for name in ("order_create", "order_create_with_item", "order_create_preview"):
            with self.subTest(endpoint=name):
                response = self.client.post(reverse(f"orders:{name}"), self.order_payload("RON", old.revision))
                self.assertEqual(response.status_code, 409)
                self.assertFalse(Order.objects.exists())

    def test_same_currency_old_revision_and_missing_revision_are_rejected(self) -> None:
        old = get_selling_currency_policy()
        self.switch("EUR")
        self.switch("RON")
        for revision in (old.revision, None):
            with self.subTest(revision=revision):
                data = self.order_payload("RON", old.revision)
                if revision is None:
                    data.pop("currency_revision")
                response = self.client.post(reverse("orders:order_create"), data)
                self.assertEqual(response.status_code, 409)
                self.assertFalse(Order.objects.exists())

    def test_staff_service_creation_uses_current_explicit_price(self) -> None:
        policy = self.switch("USD")
        response = self.client.post(reverse("provisioning:service_create"), {
            "customer_id": self.customer.pk, "plan_id": self.plan.pk, "domain": "currency.example.test",
            "currency": "USD", "currency_revision": policy.revision,
        })
        self.assertEqual(response.status_code, 302)
        service = Service.objects.get()
        self.assertEqual((service.currency_id, service.price), ("USD", Decimal("12.00")))

    def test_staff_service_creation_rejects_stale_form(self) -> None:
        old = get_selling_currency_policy()
        self.switch("EUR")
        response = self.client.post(reverse("provisioning:service_create"), {
            "customer_id": self.customer.pk, "plan_id": self.plan.pk, "domain": "currency.example.test",
            "currency": "RON", "currency_revision": old.revision,
        })
        self.assertEqual(response.status_code, 409)
        self.assertFalse(Service.objects.exists())

    def test_staff_service_detail_displays_original_charge_after_switch(self) -> None:
        service = Service.objects.create(
            customer=self.customer, service_plan=self.plan, currency_id="EUR", price=Decimal("9.00"),
            service_name="Original euro service", username="original_euro", domain="original.example.test",
        )
        self.switch("USD")
        response = self.client.get(reverse("provisioning:service_detail", kwargs={"pk": service.pk}))
        self.assertContains(response, "9,00 EUR")
        self.assertNotContains(response, "50,00 RON")
