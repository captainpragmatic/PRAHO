"""Tests for audited manual FX-rate ingestion."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from io import StringIO
from unittest.mock import patch

from django.core.management import CommandError, call_command
from django.test import TestCase

from apps.billing.models import Currency, FXRate


class RecordExchangeRateCommandTest(TestCase):
    def setUp(self) -> None:
        Currency.objects.get_or_create(code="EUR", defaults={"name": "Euro", "symbol": "EUR", "decimals": 2})
        Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian leu", "symbol": "lei", "decimals": 2})
        self.args = (
            "record_exchange_rate",
            "--base",
            "EUR",
            "--quote",
            "RON",
            "--rate",
            "5.0123",
            "--as-of",
            "2026-07-17",
            "--source",
            "bnr",
            "--reference",
            "https://www.bnr.ro/nbrfxrates.xml",
            "--recorded-by",
            "finance@example.test",
        )

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_command_records_provenance_and_audits_context(self, audit_log: object) -> None:
        output = StringIO()

        call_command(*self.args, stdout=output)

        rate = FXRate.objects.get(base_code_id="EUR", quote_code_id="RON", as_of=date(2026, 7, 17))
        self.assertEqual(rate.rate, Decimal("5.01230000"))
        self.assertEqual(rate.source, FXRate.Source.BNR)
        self.assertEqual(rate.source_reference, "https://www.bnr.ro/nbrfxrates.xml")
        self.assertIsNotNone(rate.fetched_at)
        audit_log.assert_called_once()
        args = audit_log.call_args.args
        kwargs = audit_log.call_args.kwargs
        self.assertEqual(args[0], "fx_rate_recorded")
        self.assertEqual(kwargs["content_object"], rate)
        self.assertEqual(kwargs["metadata"]["recorded_by"], "finance@example.test")
        self.assertIn("Recorded EUR/RON", output.getvalue())

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_exact_replay_is_idempotent(self, audit_log: object) -> None:
        call_command(*self.args)
        first = FXRate.objects.get(base_code_id="EUR", quote_code_id="RON", as_of=date(2026, 7, 17))

        call_command(*self.args)

        self.assertEqual(FXRate.objects.count(), 1)
        self.assertEqual(FXRate.objects.get().pk, first.pk)
        audit_log.assert_called_once()

    @patch("apps.audit.services.AuditService.log_simple_event")
    def test_conflicting_historical_value_is_refused(self, audit_log: object) -> None:
        call_command(*self.args)
        conflicting_args = tuple("5.0999" if value == "5.0123" else value for value in self.args)

        with self.assertRaisesRegex(CommandError, "already exists with different"):
            call_command(*conflicting_args)

        self.assertEqual(FXRate.objects.get().rate, Decimal("5.01230000"))
        audit_log.assert_called_once()

    def test_command_rejects_non_statutory_source(self) -> None:
        for invalid_source in ("legacy_unknown", "manual"):
            invalid_args = tuple(invalid_source if value == "bnr" else value for value in self.args)

            with self.subTest(source=invalid_source), self.assertRaises(CommandError):
                call_command(*invalid_args)

        self.assertFalse(FXRate.objects.exists())

    def test_command_rejects_non_finite_rates(self) -> None:
        for invalid_rate in ("NaN", "Infinity"):
            invalid_args = tuple(invalid_rate if value == "5.0123" else value for value in self.args)

            with self.subTest(rate=invalid_rate), self.assertRaisesRegex(CommandError, "finite and positive"):
                call_command(*invalid_args)

        self.assertFalse(FXRate.objects.exists())
