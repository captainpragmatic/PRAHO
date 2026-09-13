"""FX-rate freshness subsystem check + staleness alert (#103)."""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.common.system_status import StatusLevel, SubsystemStatus, _check_fx_freshness
from apps.common.tasks import _FX_FRESHNESS_ALERT_KEY, _alert_on_fx_freshness
from config.settings.test import LOCMEM_TEST_CACHE

_PAIRS = "apps.settings.services.SettingsService.get_list_setting"
_STALE = "apps.settings.services.SettingsService.get_integer_setting"
_ALERT = "apps.notifications.services.NotificationService.send_admin_alert"


@patch(_PAIRS, return_value=["EUR"])
class FxFreshnessCheckTests(TestCase):
    def setUp(self) -> None:
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€", "decimals": 2})
        self.ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.today = timezone.localdate()

    def _rate(self, as_of, *, source=FXRate.Source.BNR, provenanced=True) -> None:
        FXRate.objects.create(
            base_code=self.eur, quote_code=self.ron, rate=Decimal("5.00000000"), as_of=as_of,
            source=source, source_reference="ref" if provenanced else "",
            fetched_at=timezone.now() if provenanced else None,
        )

    def test_green_when_fresh(self, _pairs: object) -> None:
        self._rate(self.today - timedelta(days=1))
        self.assertEqual(_check_fx_freshness().level, StatusLevel.GREEN)

    def test_red_when_missing(self, _pairs: object) -> None:
        self.assertEqual(_check_fx_freshness().level, StatusLevel.RED)

    def test_red_when_only_a_future_rate_exists(self, _pairs: object) -> None:
        # Counterexample: tomorrow's rate exists, none valid today.
        self._rate(self.today + timedelta(days=1))
        self.assertEqual(_check_fx_freshness().level, StatusLevel.RED)

    def test_red_when_unprovenanced_row_shadows_older_approved(self, _pairs: object) -> None:
        # Counterexample: today's latest row is legacy/unprovenanced; an older approved row
        # exists but resolve() picks the latest → unusable today → RED (a "latest date"
        # check would wrongly report GREEN).
        self._rate(self.today - timedelta(days=5))
        self._rate(self.today, source=FXRate.Source.LEGACY_UNKNOWN, provenanced=False)
        self.assertEqual(_check_fx_freshness().level, StatusLevel.RED)

    @patch(_STALE, return_value=2)
    def test_amber_when_stale(self, _stale: object, _pairs: object) -> None:
        self._rate(self.today - timedelta(days=10))
        self.assertEqual(_check_fx_freshness().level, StatusLevel.AMBER)

    def test_grey_when_no_foreign_pairs(self, pairs: object) -> None:
        pairs.return_value = ["RON"]
        self.assertEqual(_check_fx_freshness().level, StatusLevel.GREY)


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class FxFreshnessAlertTests(TestCase):
    def _status(self, level: StatusLevel) -> list[SubsystemStatus]:
        return [SubsystemStatus(name="FX rates", level=level, message="m", detail="d")]

    def setUp(self) -> None:
        cache.delete(_FX_FRESHNESS_ALERT_KEY)

    @patch(_ALERT, return_value=True)
    def test_alerts_once_per_level_then_dedups(self, mock_alert: object) -> None:
        _alert_on_fx_freshness(self._status(StatusLevel.RED), 3600)
        _alert_on_fx_freshness(self._status(StatusLevel.RED), 3600)
        mock_alert.assert_called_once()

    @patch(_ALERT, return_value=True)
    def test_recovery_resets_then_realerts(self, mock_alert: object) -> None:
        _alert_on_fx_freshness(self._status(StatusLevel.RED), 3600)
        _alert_on_fx_freshness(self._status(StatusLevel.GREEN), 3600)  # recovery clears dedup
        _alert_on_fx_freshness(self._status(StatusLevel.RED), 3600)
        self.assertEqual(mock_alert.call_count, 2)
