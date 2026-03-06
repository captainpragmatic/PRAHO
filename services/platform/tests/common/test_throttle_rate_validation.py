from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from apps.common.apps import _validate_throttle_rates_at_startup
from apps.common.performance.rate_limiting import (
    PortalHMACRateThrottle,
    parse_rate_string,
    validate_throttle_class_scopes,
    validate_throttle_rate_map,
)
from apps.common.retry_after import coerce_retry_after_seconds


class ThrottleRateParsingTests(SimpleTestCase):
    def test_parse_rate_string_supports_custom_window_notation(self) -> None:
        self.assertEqual(parse_rate_string("50/10s"), (50, 10))
        self.assertEqual(parse_rate_string("100/minute"), (100, 60))

    def test_parse_rate_string_rejects_unknown_period_suffix(self) -> None:
        with self.assertRaises(ValueError):
            parse_rate_string("100/week")

    def test_validate_throttle_rate_map_rejects_empty_or_invalid_rates(self) -> None:
        with self.assertRaises(ImproperlyConfigured):
            validate_throttle_rate_map({"portal_hmac": "", "user": "100/week"})


class StartupThrottleValidationTests(SimpleTestCase):
    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_THROTTLE_CLASSES": [
                "apps.common.performance.rate_limiting.PortalHMACRateThrottle",
                "apps.common.performance.rate_limiting.PortalHMACBurstThrottle",
                "apps.common.performance.rate_limiting.CustomerRateThrottle",
                "apps.common.performance.rate_limiting.BurstRateThrottle",
            ],
            "DEFAULT_THROTTLE_RATES": {
                "portal_hmac": "100/minute",
                "portal_hmac_burst": "50/10s",
                "customer": "100/minute",
                "burst": "30/10s",
                "auth": "5/minute",
                "sustained": "1000/hour",
                "api_burst": "60/min",
                "anon": "20/minute",
                "order_create": "10/min",
                "order_calculate": "30/min",
                "order_list": "100/min",
                "product_catalog": "200/min",
            },
        }
    )
    def test_startup_validation_allows_valid_rates(self) -> None:
        _validate_throttle_rates_at_startup()

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_THROTTLE_CLASSES": ["apps.common.performance.rate_limiting.PortalHMACRateThrottle"],
            "DEFAULT_THROTTLE_RATES": {"portal_hmac": "100/week"},
        }
    )
    def test_startup_validation_rejects_invalid_rates(self) -> None:
        with self.assertRaises(ImproperlyConfigured):
            _validate_throttle_rates_at_startup()

    def test_validate_throttle_class_scopes_rejects_unknown_scope(self) -> None:
        with self.assertRaises(ImproperlyConfigured):
            validate_throttle_class_scopes(
                ["apps.common.performance.rate_limiting.StandardAPIThrottle"],
                {"auth": "5/minute"},
            )

    def test_validate_throttle_class_scopes_accepts_class_objects(self) -> None:
        validate_throttle_class_scopes(
            [PortalHMACRateThrottle],
            {"portal_hmac": "100/minute"},
        )

    @override_settings(
        REST_FRAMEWORK={
            "DEFAULT_THROTTLE_CLASSES": (
                "apps.common.performance.rate_limiting.PortalHMACRateThrottle",
                "apps.common.performance.rate_limiting.PortalHMACBurstThrottle",
                "apps.common.performance.rate_limiting.CustomerRateThrottle",
                "apps.common.performance.rate_limiting.BurstRateThrottle",
            ),
            "DEFAULT_THROTTLE_RATES": {
                "portal_hmac": "100/minute",
                "portal_hmac_burst": "50/10s",
                "customer": "100/minute",
                "burst": "30/10s",
                "auth": "5/minute",
                "sustained": "1000/hour",
                "api_burst": "60/min",
                "anon": "20/minute",
                "order_create": "10/min",
                "order_calculate": "30/min",
                "order_list": "100/min",
                "product_catalog": "200/min",
            },
        }
    )
    def test_startup_validation_accepts_tuple_default_classes(self) -> None:
        _validate_throttle_rates_at_startup()


class RetryAfterParsingTests(SimpleTestCase):
    def test_coerce_retry_after_seconds_supports_http_date(self) -> None:
        retry_header = format_datetime(datetime.now(UTC) + timedelta(seconds=9), usegmt=True)

        retry_after = coerce_retry_after_seconds(retry_header)

        self.assertIsNotNone(retry_after)
        self.assertGreaterEqual(retry_after or 0, 1)
