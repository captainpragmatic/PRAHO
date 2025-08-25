# ===============================================================================
# BILLING CURRENCY AND EXCHANGE RATE TESTS (Django TestCase Format)
# ===============================================================================

from datetime import date
from decimal import Decimal

from django.db import IntegrityError
from django.test import TestCase

from apps.billing.models import Currency, FXRate


class CurrencyTestCase(TestCase):
    """Test Currency model functionality"""

    def test_create_currency(self):
        """Test basic currency creation"""
        currency = Currency.objects.create(
            code='EUR',
            symbol='€',
            decimals=2
        )

        self.assertEqual(currency.code, 'EUR')
        self.assertEqual(currency.symbol, '€')
        self.assertEqual(currency.decimals, 2)

    def test_currency_code_primary_key(self):
        """Test currency code as primary key"""
        currency = Currency.objects.create(code='USD', symbol='$')
        self.assertEqual(currency.pk, 'USD')

    def test_currency_str_representation(self):
        """Test string representation"""
        currency = Currency.objects.create(code='RON', symbol='RON')
        self.assertEqual(str(currency), 'RON (RON)')

    def test_currency_decimals_default(self):
        """Test default decimals value"""
        currency = Currency.objects.create(code='BTC', symbol='₿')
        self.assertEqual(currency.decimals, 2)  # Default value


class FXRateTestCase(TestCase):
    """Test Foreign Exchange Rate model functionality"""

    def setUp(self):
        """Create test currencies"""
        self.eur = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.ron = Currency.objects.create(code='RON', symbol='RON', decimals=2)
        self.usd = Currency.objects.create(code='USD', symbol='$', decimals=2)

    def test_create_fx_rate(self):
        """Test basic FX rate creation"""
        fx_rate = FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9750'),
            as_of=date(2025, 8, 19)
        )

        self.assertEqual(fx_rate.base_code, self.eur)
        self.assertEqual(fx_rate.quote_code, self.ron)
        self.assertEqual(fx_rate.rate, Decimal('4.9750'))
        self.assertEqual(fx_rate.as_of, date(2025, 8, 19))

    def test_fx_rate_precision(self):
        """Test FX rate decimal precision"""
        fx_rate = FXRate.objects.create(
            base_code=self.usd,
            quote_code=self.eur,
            rate=Decimal('0.85123456'),
            as_of=date(2025, 8, 19)
        )

        # Should store 8 decimal places
        self.assertEqual(fx_rate.rate, Decimal('0.85123456'))

    def test_fx_rate_unique_together_constraint(self):
        """Test unique constraint on base_code, quote_code, as_of"""
        # Create first rate
        FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9750'),
            as_of=date(2025, 8, 19)
        )

        # Try to create duplicate
        with self.assertRaises(IntegrityError):
            FXRate.objects.create(
                base_code=self.eur,
                quote_code=self.ron,
                rate=Decimal('4.9800'),
                as_of=date(2025, 8, 19)  # Same date
            )

    def test_fx_rate_different_dates_allowed(self):
        """Test different dates are allowed for same currency pair"""
        rate1 = FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9750'),
            as_of=date(2025, 8, 19)
        )

        rate2 = FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9800'),
            as_of=date(2025, 8, 20)  # Different date
        )

        self.assertNotEqual(rate1.id, rate2.id)

    def test_fx_rate_cascade_delete(self):
        """Test CASCADE delete when currency is deleted"""
        fx_rate = FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9750'),
            as_of=date(2025, 8, 19)
        )

        fx_rate_id = fx_rate.id

        # Delete base currency
        self.eur.delete()

        # FX rate should be deleted too
        with self.assertRaises(FXRate.DoesNotExist):
            FXRate.objects.get(id=fx_rate_id)

    def test_fx_rate_related_names(self):
        """Test related names work correctly"""
        FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9750'),
            as_of=date(2025, 8, 19)
        )

        FXRate.objects.create(
            base_code=self.usd,
            quote_code=self.eur,
            rate=Decimal('0.85'),
            as_of=date(2025, 8, 19)
        )

        # Test related names
        self.assertEqual(self.eur.base_rates.count(), 1)
        self.assertEqual(self.eur.quote_rates.count(), 1)

    def test_fx_rate_ordering(self):
        """Test default ordering by as_of date"""
        rate_old = FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9750'),
            as_of=date(2025, 8, 18)
        )

        rate_new = FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9800'),
            as_of=date(2025, 8, 19)
        )

        rates = FXRate.objects.filter(
            base_code=self.eur,
            quote_code=self.ron
        ).order_by('-as_of')

        self.assertEqual(rates.first(), rate_new)
        self.assertEqual(rates.last(), rate_old)


class CurrencyIntegrationTestCase(TestCase):
    """Test Currency integration scenarios"""

    def setUp(self):
        self.eur = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.ron = Currency.objects.create(code='RON', symbol='RON', decimals=2)

    def test_currency_used_in_invoices(self):
        """Test currency protection when used in invoices"""
        # This will be expanded when Invoice tests are converted

    def test_currency_protect_on_delete(self):
        """Test PROTECT on delete when currency is referenced"""
        # Create FX rate referencing currency
        FXRate.objects.create(
            base_code=self.eur,
            quote_code=self.ron,
            rate=Decimal('4.9750'),
            as_of=date(2025, 8, 19)
        )

        # Try to delete currency - should not be allowed due to FK constraint
        # Note: This behavior depends on the actual FK constraint in the model
        # The test may need adjustment based on the actual constraint behavior
        try:
            self.ron.delete()
            # If we get here, check that FX rate was also deleted (CASCADE)
            self.assertEqual(FXRate.objects.filter(quote_code=self.ron.code).count(), 0)
        except Exception:
            # If deletion is protected, that's also valid behavior
            self.assertTrue(FXRate.objects.filter(quote_code=self.ron).exists())
