"""Unit tests for the shared record_fx_rate() immutable writer (#103)."""

from datetime import date
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.billing.currency_models import Currency, FXRate
from apps.billing.fx_rate_ingestion import (
    FXRateConflictError,
    FXRatePromotionRequiredError,
    record_fx_rate,
)

_AS_OF = date(2026, 9, 12)
_REF = "https://curs.bnr.ro/nbrfxrates.xml"


class RecordFxRateTests(TestCase):
    def setUp(self) -> None:
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        self.ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})

    def _record(self, rate="5.25570000", source=FXRate.Source.BNR, reference=_REF):
        return record_fx_rate(self.eur, self.ron, _AS_OF, Decimal(rate), source, reference, "unit-test")

    def test_new_row_persists_evidence_and_one_audit(self) -> None:
        row, created = self._record()
        self.assertTrue(created)
        self.assertEqual(row.rate, Decimal("5.25570000"))
        self.assertEqual(row.source, FXRate.Source.BNR)
        self.assertEqual(row.source_reference, _REF)
        self.assertIsNotNone(row.fetched_at)
        self.assertEqual(AuditEvent.objects.filter(action="fx_rate_recorded").count(), 1)

    def test_identical_replay_is_noop_without_new_audit(self) -> None:
        first, _ = self._record()
        fetched_at = first.fetched_at
        row, created = self._record()
        self.assertFalse(created)
        self.assertEqual(row.pk, first.pk)
        row.refresh_from_db()
        self.assertEqual(row.fetched_at, fetched_at)  # preserved
        self.assertEqual(AuditEvent.objects.filter(action="fx_rate_recorded").count(), 1)  # no 2nd audit

    def test_differing_rate_is_a_conflict_and_never_overwrites(self) -> None:
        self._record(rate="5.25570000")
        with self.assertRaises(FXRateConflictError):
            self._record(rate="9.99999999")
        self.assertEqual(FXRate.objects.get(base_code=self.eur, quote_code=self.ron, as_of=_AS_OF).rate,
                         Decimal("5.25570000"))

    def test_same_amount_legacy_row_requires_promotion(self) -> None:
        FXRate.objects.create(
            base_code=self.eur, quote_code=self.ron, as_of=_AS_OF, rate=Decimal("5.25570000"),
            source=FXRate.Source.LEGACY_UNKNOWN, source_reference="", fetched_at=None,
        )
        with self.assertRaises(FXRatePromotionRequiredError):
            self._record(rate="5.25570000")

    def test_invalid_source_or_blank_provenance_rejected_without_row(self) -> None:
        for kwargs in ({"source": FXRate.Source.LEGACY_UNKNOWN}, {"reference": "  "}):
            with self.subTest(**kwargs), self.assertRaises(ValidationError):
                self._record(**kwargs)
        self.assertFalse(FXRate.objects.filter(base_code=self.eur, quote_code=self.ron).exists())
        self.assertEqual(AuditEvent.objects.filter(action="fx_rate_recorded").count(), 0)
