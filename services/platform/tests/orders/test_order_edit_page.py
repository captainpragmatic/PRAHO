"""The staff order edit page and its item form work as a page, not only as POST endpoints.

- The edit view passed no payment method options, so the select held only its placeholder, and
  saving a draft order's edit page posted an empty method over the one it had.
- It passed no `can_edit`, so the item script never loaded and the items stayed read-only.
- The item form read `billing_period`, `amount_cents` and `amount` from `ProductPrice`, which has
  none of them, so opening "Add item" for any product priced in the order's currency crashed.
- `requires_domain` reached the page as "True"/"False", and the script compares with "true".
- The item form's tax preview used a literal 21% instead of the order's rate.
"""

from __future__ import annotations

import json
from datetime import date
from decimal import Decimal
from html.parser import HTMLParser
from typing import Any

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.html import escapejs

from apps.billing.models import Currency
from apps.billing.tax_models import TaxRule
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product, ProductPrice

User = get_user_model()


class _SelectOptions(HTMLParser):
    """Collect the attributes of every <option> inside the <select> with the given name."""

    def __init__(self, select_name: str) -> None:
        super().__init__()
        self.select_name = select_name
        self.inside = False
        self.options: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "select":
            self.inside = attributes.get("name") == self.select_name
        elif tag == "option" and self.inside:
            self.options.append(attributes)

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self.inside = False


def options(html: str, select_name: str) -> list[dict[str, str | None]]:
    parser = _SelectOptions(select_name)
    parser.feed(html)
    return parser.options


def submitted_value(found: list[dict[str, str | None]]) -> str:
    """What a browser posts for a single select: the selected option, else the first one."""
    chosen = [option for option in found if "selected" in option] or found[:1]
    return chosen[0].get("value") or "" if chosen else ""


class OrderPageTestBase(TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Edit Page SRL", customer_type="company", status="active", primary_email="edit@example.test"
        )
        self.staff = User.objects.create_user(
            email="orders-admin@example.test", password="unused-pass", staff_role="admin", is_superuser=True
        )
        self.order = Order.objects.create(
            customer=self.customer, currency=self.currency, status="draft", payment_method="bank_transfer"
        )
        self.client.force_login(self.staff)


class OrderEditPageTests(OrderPageTestBase):
    def edit_page(self) -> str:
        response = self.client.get(reverse("orders:order_edit", kwargs={"pk": self.order.pk}))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_every_payment_method_is_offered_with_the_current_one_selected(self) -> None:
        found = options(self.edit_page(), "payment_method")

        choices = [value for value, _label in Order._meta.get_field("payment_method").choices]
        self.assertEqual([option["value"] for option in found if option["value"]], choices)
        self.assertEqual([option["value"] for option in found if "selected" in option], ["bank_transfer"])

    def test_saving_the_page_keeps_the_payment_method(self) -> None:
        posted = submitted_value(options(self.edit_page(), "payment_method"))

        response = self.client.post(
            reverse("orders:order_edit", kwargs={"pk": self.order.pk}),
            {"payment_method": posted, "notes": "Called the customer"},
        )

        self.assertEqual(response.status_code, 302)
        self.order.refresh_from_db()
        self.assertEqual(self.order.notes, "Called the customer")
        self.assertEqual(self.order.payment_method, "bank_transfer")

    def test_the_item_script_loads_with_the_order_url(self) -> None:
        html = self.edit_page()

        self.assertIn("js/orders-items.js", html)
        self.assertIn("window.PRAHO_ORDER_ITEMS", html)
        # The script builds every item request from this URL; it used to hard-code a wrong prefix.
        order_url = reverse("orders:order_detail", kwargs={"pk": self.order.pk})
        self.assertEqual(order_url, f"/orders/{self.order.pk}/")
        self.assertIn(f'orderUrl: "{escapejs(order_url)}"', html)


class ItemFormTestBase(OrderPageTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.hosting = Product.objects.create(
            slug="edit-page-hosting", name="Edit Hosting", product_type="hosting", is_active=True, requires_domain=True
        )
        ProductPrice.objects.create(
            product=self.hosting,
            currency=self.currency,
            monthly_price_cents=1_000,
            setup_cents=500,
            semiannual_discount_percent=0,
            annual_discount_percent=10,
            is_active=True,
        )
        self.addon = Product.objects.create(
            slug="edit-page-addon", name="Edit Addon", product_type="addon", is_active=True, requires_domain=False
        )

    def item_form(self, *, inline: bool) -> str:
        headers = {"HTTP_HX_REQUEST": "true"} if inline else {}
        response = self.client.get(reverse("orders:order_item_create", kwargs={"pk": self.order.pk}), **headers)
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def product_option(self, html: str, product: Product) -> dict[str, Any]:
        [option] = [option for option in options(html, "product") if option.get("value") == str(product.pk)]
        return option


class OrderItemFormTests(ItemFormTestBase):
    def test_the_form_opens_with_the_catalog_price_for_each_period(self) -> None:
        # The prices the server accepts without an override: monthly, six months, a year at 10% off.
        # Quarterly has no price and the two- and three-year periods are not supported, so they are absent.
        expected = {
            "monthly": {"unit_cents": 1_000, "setup_cents": 500},
            "semiannual": {"unit_cents": 6_000, "setup_cents": 500},
            "annual": {"unit_cents": 10_800, "setup_cents": 500},
        }
        for inline in (True, False):
            with self.subTest(inline=inline):
                option = self.product_option(self.item_form(inline=inline), self.hosting)
                self.assertEqual(json.loads(option["data-prices"]), expected)

    def test_requires_domain_reaches_the_script_as_true_or_false(self) -> None:
        inline = self.item_form(inline=True)
        self.assertEqual(self.product_option(inline, self.hosting)["data-requires-domain"], "true")
        self.assertEqual(self.product_option(inline, self.addon)["data-requires-domain"], "false")

        full_page = self.item_form(inline=False)
        self.assertEqual(self.product_option(full_page, self.hosting)["data-requires_domain"], "true")
        self.assertEqual(self.product_option(full_page, self.addon)["data-requires_domain"], "false")

    @override_settings(COMPANY_COUNTRY_CODE="DE")
    def test_the_tax_preview_uses_the_rate_the_item_is_saved_with(self) -> None:
        # The preview multiplied by a literal 0.21 and said "VAT (21%)" whatever the order's rate.
        TaxRule.objects.create(country_code="DE", rate=Decimal("0.19"), valid_from=date(2020, 1, 1))
        self.order.billing_address = {"country": "DE"}
        self.order.save(update_fields=["billing_address"])
        self.staff.profile.preferred_language = "ro"  # a localised "0,1900" breaks the script
        self.staff.profile.save()

        html = self.item_form(inline=False)

        # The script reads the rate from json_script, so a Romanian locale cannot turn it into "0,1900".
        self.assertIn('<script id="order-item-vat-rate" type="application/json">"0.1900"</script>', html)
        self.assertNotIn("21%", html)


class OrderItemBillingPeriodTests(ItemFormTestBase):
    """The item form's billing period select is what the item is priced and saved with.

    The form behind it left the period out (it lives in `config`), so every item was saved as
    monthly, and a yearly catalog price was judged an override against the monthly one.
    """

    def setUp(self) -> None:
        super().setUp()
        self.support = User.objects.create_user(
            email="orders-support@example.test", password="unused-pass", staff_role="support"
        )

    def post_item(self, period: str, unit_cents: int) -> Any:
        self.client.force_login(self.support)
        return self.client.post(
            reverse("orders:order_item_create", kwargs={"pk": self.order.pk}),
            {
                "product": str(self.hosting.pk),
                "quantity": "1",
                "billing_period": period,
                "unit_price_cents": str(unit_cents),
                "setup_cents": "500",
                "config": "{}",
                "domain_name": "example.ro",
            },
        )

    def test_the_price_the_form_fills_in_is_accepted_without_override_permission(self) -> None:
        """What the page offers per period is what the server accepts from a support member."""
        self.client.force_login(self.support)
        page = self.client.get(
            reverse("orders:order_item_create", kwargs={"pk": self.order.pk}), HTTP_HX_REQUEST="true"
        ).content.decode()
        prices = json.loads(self.product_option(page, self.hosting)["data-prices"])

        for period, price in prices.items():
            with self.subTest(period=period):
                response = self.post_item(period, price["unit_cents"])
                self.assertEqual(response.status_code, 302, response.content[:300])
        self.assertEqual(self.order.items.count(), len(prices))

    def test_an_annual_item_is_saved_annual_at_the_annual_catalog_price(self) -> None:
        response = self.post_item("annual", 10_800)

        self.assertEqual(response.status_code, 302, response.content[:300])
        [item] = self.order.items.all()
        self.assertEqual(item.billing_period, "annual")
        self.assertEqual(item.unit_price_cents, 10_800)

    def test_changing_the_period_on_edit_reprices_through_the_override_check(self) -> None:
        """A request without the config field must not move the period past the price check.

        The period setter wrote into the config dict in place, and that same dict is the form's
        record of the original value, so the change looked like no change: no reprice and no
        override check, and a monthly item was stored as annual at the monthly price.
        """
        self.post_item("monthly", 1_000)
        item = self.order.items.get()
        self.client.force_login(self.support)

        response = self.client.post(
            reverse("orders:order_item_edit", kwargs={"pk": self.order.pk, "item_pk": item.pk}),
            {
                "product": str(self.hosting.pk),
                "quantity": "1",
                "billing_period": "annual",
                "unit_price_cents": "1000",
                "setup_cents": "500",
                "domain_name": "example.ro",
            },
        )

        self.assertIn(response.status_code, (200, 302), response.content[:300])
        item.refresh_from_db()
        self.assertEqual((item.billing_period, item.unit_price_cents), ("annual", 10_800))

    def test_the_form_offers_only_periods_an_order_can_be_fulfilled_with(self) -> None:
        """Two- and three-year periods have no service cycle, so a paid order with one could not
        be provisioned; the form offered them anyway."""
        from apps.orders.services import _order_item_billing_period  # noqa: PLC0415

        offered = [
            option["value"] for option in options(self.item_form(inline=True), "billing_period") if option["value"]
        ]

        self.assertCountEqual(offered, ["once", "monthly", "quarterly", "semiannual", "annual"])
        for period in offered:
            with self.subTest(period=period):
                self.assertEqual(_order_item_billing_period(OrderItem(config={"billing_period": period})), period)
        self.post_item("biennial", 1_000)
        self.assertEqual(self.order.items.get().billing_period, "monthly")

    def test_an_unknown_period_falls_back_to_the_stored_default(self) -> None:
        response = self.post_item("fortnightly", 1_000)

        self.assertEqual(response.status_code, 302, response.content[:300])
        self.assertEqual(self.order.items.get().billing_period, "monthly")

    def test_the_edit_form_preselects_the_item_period(self) -> None:
        self.post_item("annual", 10_800)
        item = self.order.items.get()
        self.client.force_login(self.staff)

        response = self.client.get(
            reverse("orders:order_item_edit", kwargs={"pk": self.order.pk, "item_pk": item.pk}), HTTP_HX_REQUEST="true"
        )

        found = options(response.content.decode(), "billing_period")
        self.assertEqual([option["value"] for option in found if "selected" in option], ["annual"])


class OrderItemsListRefreshTests(ItemFormTestBase):
    """The list the script refetches after an add or edit keeps the edit page's controls.

    The controls were gated on the URL being the edit page, and the refresh comes from the items
    URL, so after the first add the Edit, Delete and Add buttons vanished until a reload.
    """

    def setUp(self) -> None:
        super().setUp()
        self.item = OrderItem.objects.create(
            order=self.order,
            product=self.hosting,
            product_name=self.hosting.name,
            product_type=self.hosting.product_type,
            quantity=1,
            unit_price_cents=1_000,
            setup_cents=500,
        )

    def items_list(self, query: str = "") -> str:
        url = reverse("orders:order_items_list", kwargs={"pk": self.order.pk}) + query
        response = self.client.get(url, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_the_edit_page_refresh_keeps_the_item_controls(self) -> None:
        html = self.items_list("?mode=edit")

        self.assertIn(f'id="edit-btn-{self.item.pk}"', html)
        self.assertIn('data-invoke="deleteOrderItemAction"', html)
        self.assertIn('id="add-item-btn"', html)

    def test_without_edit_mode_the_list_is_read_only(self) -> None:
        html = self.items_list()

        self.assertNotIn(f'id="edit-btn-{self.item.pk}"', html)
        self.assertNotIn('id="add-item-btn"', html)

    def test_the_detail_page_loads_no_item_script(self) -> None:
        response = self.client.get(reverse("orders:order_detail", kwargs={"pk": self.order.pk}))

        self.assertNotIn("js/orders-items.js", response.content.decode())
