"""Scheduled BNR fetch task: flag gating, ingestion, failover, scheduling (#103)."""

import uuid
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone
from django_q.models import Schedule

from apps.billing.currency_models import Currency, FXRate
from apps.billing.gateways.bnr_gateway import BNRResponse
from apps.billing.tasks import fetch_bnr_exchange_rates, setup_fx_scheduled_tasks

_FLAG = "apps.settings.services.SettingsService.get_boolean_setting"
_PAIRS = "apps.settings.services.SettingsService.get_list_setting"
_FETCH = "apps.billing.gateways.bnr_gateway.BNRGateway.fetch_rates"
_ALERT = "apps.notifications.services.NotificationService.send_admin_alert"


class FetchBnrExchangeRatesTaskTests(TestCase):
    def setUp(self) -> None:
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        self.ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})

    @patch(_FLAG, return_value=False)
    def test_disabled_is_noop(self, _flag: object) -> None:
        result = fetch_bnr_exchange_rates()
        self.assertEqual(result["skipped"], "disabled")
        self.assertFalse(FXRate.objects.exists())

    @patch(_FETCH)
    @patch(_PAIRS, return_value=["EUR"])
    @patch(_FLAG, return_value=True)
    def test_records_rate_with_calendar_day_as_of(self, _flag: object, _pairs: object, mock_fetch: object) -> None:
        mock_fetch.return_value = BNRResponse(
            publication_date=date(2026, 9, 11), rates={"EUR": Decimal("5.2557")}, api_available=True
        )
        result = fetch_bnr_exchange_rates()
        self.assertTrue(result["success"], result)
        row = FXRate.objects.get(base_code=self.eur, quote_code=self.ron)
        self.assertEqual(row.as_of, date(2026, 9, 12))  # publication + 1 CALENDAR day
        self.assertEqual(row.rate, Decimal("5.2557"))
        self.assertEqual(row.source, FXRate.Source.BNR)

    @patch(_ALERT, return_value=True)
    @patch(_FETCH)
    @patch(_PAIRS, return_value=["EUR"])
    @patch(_FLAG, return_value=True)
    def test_unavailable_feed_alerts_and_writes_nothing(
        self, _flag: object, _pairs: object, mock_fetch: object, mock_alert: object
    ) -> None:
        mock_fetch.return_value = BNRResponse(api_available=False, error_message="feed unavailable")
        result = fetch_bnr_exchange_rates()
        self.assertFalse(result["success"])
        self.assertFalse(FXRate.objects.exists())  # last-good retained
        mock_alert.assert_called_once()

    @patch(_ALERT, return_value=True)
    @patch(_FETCH)
    @patch(_PAIRS, return_value=["EUR"])
    @patch(_FLAG, return_value=True)
    def test_outbound_security_block_alerts_then_reraises(
        self, _flag: object, _pairs: object, mock_fetch: object, mock_alert: object
    ) -> None:
        # An SSRF/policy block must alert staff (docstring contract) AND re-raise so the
        # security event stays loud in the task record — not be swallowed.
        from apps.common.outbound_http import OutboundSecurityError  # noqa: PLC0415

        mock_fetch.side_effect = OutboundSecurityError("blocked host")
        with self.assertRaises(OutboundSecurityError):
            fetch_bnr_exchange_rates()
        mock_alert.assert_called_once()
        self.assertFalse(FXRate.objects.exists())

    @patch("apps.billing.tasks.DistributedLock.acquire", return_value=False)
    @patch(_FLAG, return_value=True)
    def test_lock_held_skips(self, _flag: object, _acquire: object) -> None:
        result = fetch_bnr_exchange_rates()
        self.assertEqual(result["skipped"], "locked")
        self.assertFalse(FXRate.objects.exists())

    def test_setup_registers_daily_cron(self) -> None:
        setup_fx_scheduled_tasks()
        schedule = Schedule.objects.get(name="fx-bnr-daily-fetch")
        self.assertEqual(schedule.func, "apps.billing.tasks.fetch_bnr_exchange_rates")
        self.assertEqual(schedule.schedule_type, Schedule.CRON)

    @patch(_ALERT, return_value=True)
    @patch(_FETCH)
    @patch(_PAIRS, return_value=["EUR", "USD"])
    @patch(_FLAG, return_value=True)
    def test_conflict_midbatch_rolls_back_whole_publication(
        self, _flag: object, _pairs: object, mock_fetch: object, mock_alert: object
    ) -> None:
        # H2: a conflict on USD must roll back the EUR write from the same publication.
        usd, _ = Currency.objects.get_or_create(code="USD", defaults={"symbol": "$", "decimals": 2})
        FXRate.objects.create(  # a DIFFERENT USD rate already stored at the publication+1 as_of
            base_code=usd, quote_code=self.ron, rate=Decimal("9.9999"), as_of=date(2026, 9, 12),
            source=FXRate.Source.BNR, source_reference="prior", fetched_at=timezone.now(),
        )
        mock_fetch.return_value = BNRResponse(
            publication_date=date(2026, 9, 11),
            rates={"EUR": Decimal("5.2557"), "USD": Decimal("4.5316")},  # USD conflicts
            api_available=True,
        )
        result = fetch_bnr_exchange_rates()
        self.assertFalse(result["success"], result)
        # EUR iterates first; per-currency commits would leave it — the atomic batch must not.
        self.assertFalse(FXRate.objects.filter(base_code=self.eur).exists())
        mock_alert.assert_called_once()

    @patch(_ALERT, return_value=True)
    @patch(_FETCH)
    @patch(_PAIRS, return_value=["EUR", "USD"])
    @patch(_FLAG, return_value=True)
    def test_precision_failure_midbatch_alerts_and_writes_nothing(
        self, _flag: object, _pairs: object, mock_fetch: object, mock_alert: object
    ) -> None:
        # H2: a >8-decimal rate clears the gateway but trips the model precision validator —
        # a ValidationError (not FXRateConflictError) must still roll back and alert, never escape.
        Currency.objects.get_or_create(code="USD", defaults={"symbol": "$", "decimals": 2})
        mock_fetch.return_value = BNRResponse(
            publication_date=date(2026, 9, 11),
            rates={"EUR": Decimal("5.2557"), "USD": Decimal("4.531600001")},  # 9 decimal places
            api_available=True,
        )
        result = fetch_bnr_exchange_rates()
        self.assertFalse(result["success"], result)
        self.assertFalse(FXRate.objects.filter(base_code=self.eur).exists())
        mock_alert.assert_called_once()

    def test_unbound_replay_fails_closed_on_unresolvable_currency(self) -> None:
        # H1: the crash-recovery replay may create the FIRST real charge — it must fail
        # closed on an unresolvable non-RON rate BEFORE touching the gateway.
        from apps.billing.currency_service import CurrencyNotIssuableError  # noqa: PLC0415
        from apps.billing.payment_models import Payment, RecurringPaymentSubmission  # noqa: PLC0415
        from apps.billing.tasks import _replay_unbound_recurring_submission  # noqa: PLC0415
        from apps.customers.models import Customer  # noqa: PLC0415

        customer = Customer.objects.create(
            customer_type="company", company_name="Replay SRL", primary_email="replay@test.ro", status="active"
        )
        payment = Payment.objects.create(customer=customer, currency=self.eur, amount_cents=12_100)
        submission = RecurringPaymentSubmission.objects.create(payment=payment)
        gateway = MagicMock()

        with self.assertRaises(CurrencyNotIssuableError):  # no EUR FXRate exists → unresolvable
            _replay_unbound_recurring_submission(submission, gateway, uuid.uuid4())
        gateway.create_off_session_payment_intent.assert_not_called()
