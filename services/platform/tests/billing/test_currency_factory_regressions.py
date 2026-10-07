"""Currency factory regressions."""

from contextlib import suppress

from django.core.exceptions import FieldError
from django.test import TestCase

from apps.billing.models import Currency
from tests.factories.core_factories import create_ron_currency


class RONCurrencyFactoryTests(TestCase):
    def test_factory_creates_ron_on_an_empty_currency_table(self) -> None:
        Currency.objects.all().delete()
        currency: Currency | None = None
        with suppress(FieldError):
            currency = create_ron_currency()
        self.assertIsNotNone(currency, "create_ron_currency must accept the current Currency fields")
        assert currency is not None
        self.assertEqual(currency.code, "RON")
        self.assertEqual(currency.decimals, 2)
        self.assertEqual(Currency.objects.get(code="RON").pk, currency.pk)
        self.assertEqual(create_ron_currency().pk, currency.pk)
        self.assertEqual(Currency.objects.count(), 1)
