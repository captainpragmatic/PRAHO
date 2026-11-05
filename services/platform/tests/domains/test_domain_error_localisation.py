"""Unsupported-TLD refusals resolve locale late and preserve the rejected input."""

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.translation import override

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.domains.models import Domain
from apps.domains.services import DomainLifecycleService, DomainOrderService
from apps.orders.models import Order


class DomainErrorLocalisationTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(name="Translation owner", primary_email="translation@example.test")
        currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.order = Order.objects.create(
            customer=self.customer, currency=currency, order_number="ORD-TRANSLATION", customer_name=self.customer.name
        )

    def test_model_refusal_remembers_the_original_tld_and_translates_at_render_time(self) -> None:
        domain = Domain(name="example.unsupported", customer=self.customer)
        with override("en"), self.assertRaises(ValidationError) as refused:
            domain.clean()
        self.assertEqual(domain.name, "example.unsupported")
        self.assertIsNone(domain.tld_id)
        domain.name = "different.changed"
        for language, expected in (
            ("en", "TLD '.unsupported' is not supported"),
            ("ro", "TLD-ul '.unsupported' nu este acceptat"),
            ("en", "TLD '.unsupported' is not supported"),
        ):
            with self.subTest(language=language), override(language):
                self.assertEqual(refused.exception.messages, [expected])
        self.assertFalse(Domain.objects.exists())

    def test_registration_and_order_refusals_keep_lazy_locale_without_recording_a_domain(self) -> None:
        with override("en"):
            registration = DomainLifecycleService.create_domain_registration(
                customer=self.customer, domain_name="example.unsupported"
            )
            accepted, order_error = DomainOrderService.create_domain_order_item(
                self.order, "example.unsupported", "register"
            )
        self.assertTrue(registration.is_err())
        self.assertFalse(accepted)
        for language, expected in (
            ("en", "TLD '.unsupported' is not supported"),
            ("ro", "TLD-ul '.unsupported' nu este acceptat"),
            ("en", "TLD '.unsupported' is not supported"),
        ):
            with override(language):
                for operation, message in (("registration", registration.unwrap_err()), ("order", order_error)):
                    with self.subTest(language=language, operation=operation):
                        self.assertEqual(str(message), expected)
        self.assertFalse(Domain.objects.exists())
        self.assertFalse(self.order.items.exists())
