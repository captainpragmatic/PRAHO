"""Counted nouns use Romanian plural forms, not an English "s" on a translated word.

Templates wrote `{% trans "year" %}{{ n|pluralize }}`: the singular is translated ("an") and
English `pluralize` appends "s", so a Romanian page read "2 ans" and "3 articols". Romanian has
three forms (1 an, 2 ani, 20 de ani), which only a counted translation can choose.
"""

from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.template import Context, Template
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone, translation

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.orders.models import Order, OrderItem
from apps.products.models import Product

User = get_user_model()

COUNTED = {
    "year": "{{ counter }} year{% plural %}{{ counter }} years",
    "item": "{{ counter }} item{% plural %}{{ counter }} items",
    "domain": "{{ counter }} domain{% plural %}{{ counter }} domains",
}


class RomanianPluralFormsTests(SimpleTestCase):
    """The catalog holds all three Romanian forms for each counted noun the templates use."""

    def render(self, noun: str, count: int) -> str:
        source = "{% load i18n %}{% blocktrans trimmed count counter=n %}" + COUNTED[noun] + "{% endblocktrans %}"
        with translation.override("ro"):
            return Template(source).render(Context({"n": count}))

    def test_each_count_takes_its_romanian_form(self) -> None:
        expected = {
            "year": ("1 an", "2 ani", "20 de ani"),
            "item": ("1 articol", "2 articole", "20 de articole"),
            "domain": ("1 domeniu", "2 domenii", "20 de domenii"),
        }
        for noun, forms in expected.items():
            for count, form in zip((1, 2, 20), forms, strict=True):
                with self.subTest(noun=noun, count=count):
                    self.assertEqual(self.render(noun, count), form)


class RomanianPagesTests(TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.staff = User.objects.create_user(
            email="plurals-staff@example.test", password="unused-pass", staff_role="admin", is_superuser=True
        )
        self.customer = Customer.objects.create(
            name="Plurale SRL",
            company_name="Plurale SRL",
            customer_type="company",
            primary_email="plurale@example.test",
        )
        self.client.force_login(self.staff)
        session = self.client.session
        session["_language"] = "ro"
        session.save()

    def test_the_renewal_page_counts_years_in_romanian(self) -> None:
        tld = TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=1000,
            renewal_price_cents=1200,
            transfer_price_cents=800,
        )
        registrar = Registrar.objects.create(
            name="plurals-registrar",
            display_name="Plurals Registrar",
            website_url="https://plurals.example.test",
            api_endpoint="https://api.plurals.example.test",
        )
        domain = Domain.objects.create(
            name="plurale.ro",
            tld=tld,
            registrar=registrar,
            customer=self.customer,
            status="active",
            registrar_domain_id="PLURALS-1",
            expires_at=timezone.now() + timedelta(days=90),
        )

        html = self.client.get(reverse("domains:renew", kwargs={"domain_id": domain.id})).content.decode()

        self.assertIn("2 ani", html)  # the card
        self.assertIn('aria-label="2 ani"', html)  # the radio's accessible name
        self.assertIn("periodLabel: '2 ani'", html)  # the summary the script shows
        self.assertNotRegex(html, r"\b\d+ ans\b")

    def test_the_order_list_counts_items_in_romanian(self) -> None:
        product = Product.objects.create(slug="plurals-hosting", name="Plurale", product_type="addon", is_active=True)
        order = Order.objects.create(customer=self.customer, currency=self.currency, status="draft")
        for _ in range(2):
            OrderItem.objects.create(
                order=order,
                product=product,
                product_name=product.name,
                product_type=product.product_type,
                quantity=1,
                unit_price_cents=100,
                setup_cents=0,
            )

        html = self.client.get(reverse("orders:order_list")).content.decode()

        self.assertIn("2 articole", html)
        self.assertNotIn("articols", html)
