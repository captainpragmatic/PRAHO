"""Database constraints and provenance tests for fiscal exchange rates."""

from datetime import date
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, FXRate


class FXRateConstraintTestCase(TestCase):
    def setUp(self) -> None:
        self.usd, _ = Currency.objects.get_or_create(code="USD", defaults={"symbol": "$", "decimals": 2})
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "EUR", "decimals": 2})

    def test_zero_rate_is_rejected_by_database(self) -> None:
        with transaction.atomic(), self.assertRaises(IntegrityError):
            FXRate.objects.create(
                base_code=self.usd,
                quote_code=self.eur,
                rate=Decimal("0"),
                as_of=date.today(),
            )

    def test_negative_rate_is_rejected_by_database(self) -> None:
        with transaction.atomic(), self.assertRaises(IntegrityError):
            FXRate.objects.create(
                base_code=self.usd,
                quote_code=self.eur,
                rate=Decimal("-0.01"),
                as_of=date.today(),
            )

    def test_self_pair_is_rejected_by_database(self) -> None:
        with transaction.atomic(), self.assertRaises(IntegrityError):
            FXRate.objects.create(
                base_code=self.usd,
                quote_code=self.usd,
                rate=Decimal("1"),
                as_of=date.today(),
            )

    def test_non_finite_rate_is_rejected_by_model_validation(self) -> None:
        for invalid_rate in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
            rate = FXRate(
                base_code=self.usd,
                quote_code=self.eur,
                rate=invalid_rate,
                as_of=date.today(),
                source=FXRate.Source.BNR,
                source_reference="https://www.bnr.ro/nbrfxrates.xml",
                fetched_at=timezone.now(),
            )
            with self.subTest(rate=invalid_rate), self.assertRaises(ValidationError):
                rate.full_clean()

    def test_explicit_provenance_is_stored(self) -> None:
        fetched_at = timezone.now()

        fx_rate = FXRate.objects.create(
            base_code=self.usd,
            quote_code=self.eur,
            rate=Decimal("0.85"),
            as_of=date.today(),
            source=FXRate.Source.BNR,
            source_reference="https://www.bnr.ro/nbrfxrates.xml",
            fetched_at=fetched_at,
        )

        self.assertEqual(fx_rate.source, FXRate.Source.BNR)
        self.assertEqual(fx_rate.source_reference, "https://www.bnr.ro/nbrfxrates.xml")
        self.assertEqual(fx_rate.fetched_at, fetched_at)


class FXRateAsOfSemanticsTestCase(TestCase):
    """as_of is the legal validity date — the field itself must say so."""

    def test_as_of_field_documents_validity_date_semantics(self) -> None:
        help_text = str(FXRate._meta.get_field("as_of").help_text).lower()
        self.assertIn("valid", help_text)
        self.assertNotIn("publication date", help_text.replace("not the publication date", ""))
