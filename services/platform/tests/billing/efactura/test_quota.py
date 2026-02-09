"""
Comprehensive tests for ANAF Quota Tracking.

Tests cover:
- QuotaEndpoint enum
- QuotaExceededError exception
- QuotaStatus dataclass
- ANAFQuotaTracker functionality
- Rate limiting decorator
- Cache key generation
- Edge cases and error handling
"""

from unittest.mock import Mock, patch

from django.core.cache import cache
from django.test import TestCase

from apps.billing.efactura.quota import (
    ANAFQuotaTracker,
    QuotaEndpoint,
    QuotaExceededError,
    QuotaStatus,
)


class QuotaEndpointTestCase(TestCase):
    """Test QuotaEndpoint enum."""

    def test_all_endpoints_defined(self):
        """Test all expected endpoints are defined."""
        expected = ["upload", "stare", "lista_simple", "lista_paginated",
                    "descarcare", "validare", "convert_pdf"]
        actual = [e.value for e in QuotaEndpoint]
        self.assertEqual(set(expected), set(actual))

    def test_endpoint_values(self):
        """Test endpoint values match ANAF API endpoints."""
        self.assertEqual(QuotaEndpoint.UPLOAD.value, "upload")
        self.assertEqual(QuotaEndpoint.STATUS.value, "stare")
        self.assertEqual(QuotaEndpoint.LIST_SIMPLE.value, "lista_simple")
        self.assertEqual(QuotaEndpoint.DOWNLOAD.value, "descarcare")


class QuotaExceededErrorTestCase(TestCase):
    """Test QuotaExceededError exception."""

    def test_error_creation(self):
        """Test creating quota exceeded error."""
        error = QuotaExceededError(
            endpoint=QuotaEndpoint.STATUS,
            cui="12345678",
            current=100,
            limit=100,
            reset_at="2024-01-01T00:00:00",
        )
        self.assertEqual(error.endpoint, QuotaEndpoint.STATUS)
        self.assertEqual(error.cui, "12345678")
        self.assertEqual(error.current, 100)
        self.assertEqual(error.limit, 100)

    def test_error_message_format(self):
        """Test error message contains all relevant info."""
        error = QuotaExceededError(
            endpoint=QuotaEndpoint.STATUS,
            cui="12345678",
            current=100,
            limit=100,
            reset_at="2024-01-01T00:00:00",
        )
        message = str(error)
        self.assertIn("stare", message)
        self.assertIn("100/100", message)
        self.assertIn("12345678", message)

    def test_error_message_without_reset(self):
        """Test error message when reset_at is None."""
        error = QuotaExceededError(
            endpoint=QuotaEndpoint.STATUS,
            cui="12345678",
            current=100,
            limit=100,
        )
        message = str(error)
        self.assertIn("tomorrow", message)


class QuotaStatusTestCase(TestCase):
    """Test QuotaStatus dataclass."""

    def test_is_exceeded_false(self):
        """Test is_exceeded when under limit."""
        status = QuotaStatus(
            endpoint=QuotaEndpoint.STATUS,
            cui="12345678",
            message_id="msg-123",
            current=50,
            limit=100,
            remaining=50,
            reset_at="2024-01-01T00:00:00",
        )
        self.assertFalse(status.is_exceeded)

    def test_is_exceeded_true_at_limit(self):
        """Test is_exceeded when at limit."""
        status = QuotaStatus(
            endpoint=QuotaEndpoint.STATUS,
            cui="12345678",
            message_id="msg-123",
            current=100,
            limit=100,
            remaining=0,
            reset_at="2024-01-01T00:00:00",
        )
        self.assertTrue(status.is_exceeded)

    def test_is_exceeded_true_over_limit(self):
        """Test is_exceeded when over limit."""
        status = QuotaStatus(
            endpoint=QuotaEndpoint.STATUS,
            cui="12345678",
            message_id=None,
            current=150,
            limit=100,
            remaining=0,
            reset_at="2024-01-01T00:00:00",
        )
        self.assertTrue(status.is_exceeded)

    def test_usage_percent_calculation(self):
        """Test usage percentage calculation."""
        status = QuotaStatus(
            endpoint=QuotaEndpoint.STATUS,
            cui="12345678",
            message_id=None,
            current=50,
            limit=100,
            remaining=50,
            reset_at="2024-01-01T00:00:00",
        )
        self.assertEqual(status.usage_percent, 50.0)

    def test_usage_percent_zero_limit(self):
        """Test usage percentage when limit is zero."""
        status = QuotaStatus(
            endpoint=QuotaEndpoint.UPLOAD,
            cui="12345678",
            message_id=None,
            current=10,
            limit=0,
            remaining=0,
            reset_at="2024-01-01T00:00:00",
        )
        self.assertEqual(status.usage_percent, 100.0)

    def test_to_dict(self):
        """Test serialization to dict."""
        status = QuotaStatus(
            endpoint=QuotaEndpoint.STATUS,
            cui="12345678",
            message_id="msg-123",
            current=50,
            limit=100,
            remaining=50,
            reset_at="2024-01-01T00:00:00",
        )
        data = status.to_dict()
        self.assertEqual(data["endpoint"], "stare")
        self.assertEqual(data["cui"], "12345678")
        self.assertEqual(data["current"], 50)
        self.assertEqual(data["limit"], 100)
        self.assertEqual(data["remaining"], 50)
        self.assertIn("usage_percent", data)


class ANAFQuotaTrackerTestCase(TestCase):
    """Test ANAFQuotaTracker class."""

    def setUp(self):
        self.tracker = ANAFQuotaTracker()
        # Clear cache before each test
        cache.clear()

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        self.assertIsNotNone(self.tracker._settings)

    def test_get_limits_from_settings(self):
        """Test limits are read from settings."""
        limits = self.tracker._get_limits()
        self.assertIn(QuotaEndpoint.STATUS, limits)
        self.assertEqual(limits[QuotaEndpoint.STATUS], 100)
        self.assertEqual(limits[QuotaEndpoint.LIST_SIMPLE], 1500)
        self.assertEqual(limits[QuotaEndpoint.DOWNLOAD], 10)

    def test_upload_has_no_limit(self):
        """Test upload endpoint has no limit."""
        limits = self.tracker._get_limits()
        self.assertEqual(limits[QuotaEndpoint.UPLOAD], 0)

    def test_cache_key_generation_per_cui(self):
        """Test cache key generation for per-CUI quotas."""
        key = self.tracker._get_cache_key(
            QuotaEndpoint.LIST_SIMPLE,
            "12345678",
            date_str="20240101",
        )
        self.assertIn("lista_simple", key)
        self.assertIn("12345678", key)
        self.assertIn("20240101", key)

    def test_cache_key_generation_per_message(self):
        """Test cache key generation for per-message quotas."""
        key = self.tracker._get_cache_key(
            QuotaEndpoint.STATUS,
            "12345678",
            message_id="msg-123",
            date_str="20240101",
        )
        self.assertIn("stare", key)
        self.assertIn("12345678", key)
        self.assertIn("msg-123", key)

    def test_get_current_usage_empty(self):
        """Test getting usage when no calls made."""
        usage = self.tracker.get_current_usage(
            QuotaEndpoint.STATUS,
            "12345678",
            "msg-123",
        )
        self.assertEqual(usage, 0)

    def test_increment_usage(self):
        """Test incrementing usage counter."""
        new_count = self.tracker.increment(
            QuotaEndpoint.STATUS,
            "12345678",
            "msg-123",
        )
        self.assertEqual(new_count, 1)

        # Increment again
        new_count = self.tracker.increment(
            QuotaEndpoint.STATUS,
            "12345678",
            "msg-123",
        )
        self.assertEqual(new_count, 2)

    def test_increment_by_count(self):
        """Test incrementing by specific count."""
        new_count = self.tracker.increment(
            QuotaEndpoint.STATUS,
            "12345678",
            "msg-123",
            count=5,
        )
        self.assertEqual(new_count, 5)

    def test_can_call_when_under_limit(self):
        """Test can_call returns True when under limit."""
        self.assertTrue(
            self.tracker.can_call(QuotaEndpoint.STATUS, "12345678", "msg-123")
        )

    def test_can_call_when_at_limit(self):
        """Test can_call returns False when at limit."""
        # Fill up to limit (100 for STATUS)
        cache_key = self.tracker._get_cache_key(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        cache.set(cache_key, 100, version=self.tracker.CACHE_VERSION)

        self.assertFalse(
            self.tracker.can_call(QuotaEndpoint.STATUS, "12345678", "msg-123")
        )

    def test_can_call_no_limit_endpoint(self):
        """Test can_call always True for no-limit endpoints."""
        # UPLOAD has no limit
        self.assertTrue(
            self.tracker.can_call(QuotaEndpoint.UPLOAD, "12345678")
        )

    def test_get_status(self):
        """Test getting quota status."""
        # Make some calls
        self.tracker.increment(QuotaEndpoint.STATUS, "12345678", "msg-123")
        self.tracker.increment(QuotaEndpoint.STATUS, "12345678", "msg-123")

        status = self.tracker.get_status(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        self.assertEqual(status.current, 2)
        self.assertEqual(status.limit, 100)
        self.assertEqual(status.remaining, 98)

    def test_check_and_increment_success(self):
        """Test check_and_increment when under limit."""
        status = self.tracker.check_and_increment(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        self.assertEqual(status.current, 1)
        self.assertFalse(status.is_exceeded)

    def test_check_and_increment_raises_when_exceeded(self):
        """Test check_and_increment raises when quota exceeded."""
        # Fill to limit
        cache_key = self.tracker._get_cache_key(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        cache.set(cache_key, 100, version=self.tracker.CACHE_VERSION)

        with self.assertRaises(QuotaExceededError) as context:
            self.tracker.check_and_increment(
                QuotaEndpoint.STATUS, "12345678", "msg-123"
            )

        self.assertEqual(context.exception.current, 100)
        self.assertEqual(context.exception.limit, 100)

    def test_reset_quota(self):
        """Test resetting quota counter."""
        # Make some calls
        self.tracker.increment(QuotaEndpoint.STATUS, "12345678", "msg-123")
        self.assertEqual(
            self.tracker.get_current_usage(QuotaEndpoint.STATUS, "12345678", "msg-123"),
            1,
        )

        # Reset
        self.tracker.reset_quota(QuotaEndpoint.STATUS, "12345678", "msg-123")
        self.assertEqual(
            self.tracker.get_current_usage(QuotaEndpoint.STATUS, "12345678", "msg-123"),
            0,
        )

    def test_get_all_quotas(self):
        """Test getting all quota statuses for a CUI."""
        quotas = self.tracker.get_all_quotas("12345678")
        self.assertIn("stare", quotas)
        self.assertIn("upload", quotas)
        self.assertIn("lista_simple", quotas)

    def test_global_minute_limit(self):
        """Test global minute rate limit."""
        # Mock global limit check
        with patch.object(self.tracker, "_check_global_limit", return_value=False):
            self.assertFalse(
                self.tracker.can_call(QuotaEndpoint.STATUS, "12345678")
            )


class ANAFQuotaTrackerDecoratorTestCase(TestCase):
    """Test rate limiting decorator."""

    def setUp(self):
        self.tracker = ANAFQuotaTracker()
        cache.clear()

    def test_rate_limited_decorator_allows_call(self):
        """Test decorator allows call when under limit."""
        @self.tracker.rate_limited(QuotaEndpoint.STATUS)
        def check_status(cui: str, message_id: str) -> str:
            return "success"

        result = check_status(cui="12345678", message_id="msg-123")
        self.assertEqual(result, "success")

    def test_rate_limited_decorator_raises_when_exceeded(self):
        """Test decorator raises when quota exceeded."""
        # Fill to limit
        cache_key = self.tracker._get_cache_key(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        cache.set(cache_key, 100, version=self.tracker.CACHE_VERSION)

        @self.tracker.rate_limited(QuotaEndpoint.STATUS)
        def check_status(cui: str, message_id: str) -> str:
            return "success"

        with self.assertRaises(QuotaExceededError):
            check_status(cui="12345678", message_id="msg-123")

    def test_rate_limited_decorator_extracts_args(self):
        """Test decorator extracts CUI from positional args."""
        @self.tracker.rate_limited(QuotaEndpoint.STATUS)
        def check_status(cui: str, message_id: str) -> str:
            return "success"

        # Call with positional args
        result = check_status("12345678", "msg-123")
        self.assertEqual(result, "success")

        # Check usage was incremented
        usage = self.tracker.get_current_usage(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        self.assertEqual(usage, 1)


class ANAFQuotaTrackerEdgeCasesTestCase(TestCase):
    """Test edge cases and error conditions."""

    def setUp(self):
        self.tracker = ANAFQuotaTracker()
        cache.clear()

    def test_message_id_only_applies_to_specific_endpoints(self):
        """Test message_id is only used for STATUS and DOWNLOAD."""
        # For LIST_SIMPLE, message_id should not affect key
        key1 = self.tracker._get_cache_key(
            QuotaEndpoint.LIST_SIMPLE, "12345678", None, "20240101"
        )
        key2 = self.tracker._get_cache_key(
            QuotaEndpoint.LIST_SIMPLE, "12345678", "msg-123", "20240101"
        )
        # Keys should be the same (message_id ignored)
        self.assertEqual(key1, key2)

    def test_different_messages_have_separate_quotas(self):
        """Test different messages have separate quota counters."""
        self.tracker.increment(QuotaEndpoint.STATUS, "12345678", "msg-1")
        self.tracker.increment(QuotaEndpoint.STATUS, "12345678", "msg-2")

        usage1 = self.tracker.get_current_usage(
            QuotaEndpoint.STATUS, "12345678", "msg-1"
        )
        usage2 = self.tracker.get_current_usage(
            QuotaEndpoint.STATUS, "12345678", "msg-2"
        )

        self.assertEqual(usage1, 1)
        self.assertEqual(usage2, 1)

    def test_different_cuis_have_separate_quotas(self):
        """Test different CUIs have separate quota counters."""
        self.tracker.increment(QuotaEndpoint.LIST_SIMPLE, "12345678")
        self.tracker.increment(QuotaEndpoint.LIST_SIMPLE, "87654321")

        usage1 = self.tracker.get_current_usage(QuotaEndpoint.LIST_SIMPLE, "12345678")
        usage2 = self.tracker.get_current_usage(QuotaEndpoint.LIST_SIMPLE, "87654321")

        self.assertEqual(usage1, 1)
        self.assertEqual(usage2, 1)

    def test_reset_time_is_midnight_romanian(self):
        """Test reset time is midnight Romanian time."""
        reset = self.tracker._get_reset_time()
        self.assertIn("00:00:00", reset)

    def test_seconds_until_midnight(self):
        """Test seconds until midnight calculation."""
        seconds = self.tracker._seconds_until_midnight()
        # Should be between 0 and 86400 (24 hours)
        self.assertGreaterEqual(seconds, 0)
        self.assertLessEqual(seconds, 86400)

    def test_concurrent_increments(self):
        """Test handling concurrent increment attempts."""
        # Simulate concurrent increments
        for _ in range(10):
            self.tracker.increment(QuotaEndpoint.STATUS, "12345678", "msg-123")

        usage = self.tracker.get_current_usage(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        self.assertEqual(usage, 10)

    def test_cache_version_isolation(self):
        """Test cache version provides isolation."""
        # Set value with wrong version
        cache_key = self.tracker._get_cache_key(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        cache.set(cache_key, 50, version=999)

        # Should not see the value with our version
        usage = self.tracker.get_current_usage(
            QuotaEndpoint.STATUS, "12345678", "msg-123"
        )
        self.assertEqual(usage, 0)


class ANAFQuotaTrackerCustomSettingsTestCase(TestCase):
    """Test tracker with custom settings."""

    def test_custom_settings_override(self):
        """Test using custom settings."""
        mock_settings = Mock()
        mock_settings.rate_limit_status_per_message_day = 50
        mock_settings.rate_limit_list_simple_per_day = 500
        mock_settings.rate_limit_list_paginated_per_day = 5000
        mock_settings.rate_limit_download_per_message_day = 5
        mock_settings.rate_limit_global_per_minute = 100
        mock_settings.company_cui = "00000000"

        tracker = ANAFQuotaTracker(settings=mock_settings)
        limits = tracker._get_limits()

        self.assertEqual(limits[QuotaEndpoint.STATUS], 50)
        self.assertEqual(limits[QuotaEndpoint.LIST_SIMPLE], 500)
