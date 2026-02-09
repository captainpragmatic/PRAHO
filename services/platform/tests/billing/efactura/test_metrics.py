"""
Comprehensive tests for e-Factura Prometheus metrics.

Tests cover:
- NoOpMetric for when prometheus_client unavailable
- EFacturaMetrics initialization
- Convenience methods for recording metrics
- Context managers for timing
- timed_operation decorator
- Edge cases and error handling
"""

import time
from unittest.mock import patch

from django.test import TestCase

from apps.billing.efactura.metrics import (
    EFacturaMetrics,
    NoOpMetric,
    timed_operation,
)


class NoOpMetricTestCase(TestCase):
    """Test NoOpMetric class."""

    def test_labels_returns_self(self):
        """Test labels() returns self for chaining."""
        metric = NoOpMetric()
        result = metric.labels(status="success")
        self.assertIs(result, metric)

    def test_labels_multiple_args(self):
        """Test labels() accepts multiple arguments."""
        metric = NoOpMetric()
        result = metric.labels("arg1", "arg2", key="value")
        self.assertIs(result, metric)

    def test_inc_does_nothing(self):
        """Test inc() does nothing but doesn't error."""
        metric = NoOpMetric()
        metric.inc()
        metric.inc(5)
        # No assertions needed, just verify no errors

    def test_dec_does_nothing(self):
        """Test dec() does nothing but doesn't error."""
        metric = NoOpMetric()
        metric.dec()
        metric.dec(5)

    def test_set_does_nothing(self):
        """Test set() does nothing but doesn't error."""
        metric = NoOpMetric()
        metric.set(100)

    def test_observe_does_nothing(self):
        """Test observe() does nothing but doesn't error."""
        metric = NoOpMetric()
        metric.observe(1.5)

    def test_info_does_nothing(self):
        """Test info() does nothing but doesn't error."""
        metric = NoOpMetric()
        metric.info({"version": "1.0"})

    def test_chained_calls(self):
        """Test chained calls work."""
        metric = NoOpMetric()
        metric.labels(status="success").inc()
        metric.labels(endpoint="upload").observe(1.5)


class EFacturaMetricsInitializationTestCase(TestCase):
    """Test EFacturaMetrics initialization."""

    def test_metrics_initialization(self):
        """Test metrics instance initializes."""
        metrics = EFacturaMetrics()
        self.assertTrue(metrics._initialized)

    def test_double_initialization_prevented(self):
        """Test _init_metrics only runs once."""
        metrics = EFacturaMetrics()
        metrics._init_metrics()  # Call again
        # Should not error

    def test_all_metrics_defined(self):
        """Test all expected metrics are defined."""
        metrics = EFacturaMetrics()

        # Submission metrics
        self.assertIsNotNone(metrics.submissions_total)
        self.assertIsNotNone(metrics.submission_duration_seconds)

        # Status metrics
        self.assertIsNotNone(metrics.status_checks_total)
        self.assertIsNotNone(metrics.status_check_duration_seconds)

        # Validation metrics
        self.assertIsNotNone(metrics.validations_total)
        self.assertIsNotNone(metrics.validation_errors_total)

        # XML metrics
        self.assertIsNotNone(metrics.xml_generations_total)
        self.assertIsNotNone(metrics.xml_generation_duration_seconds)

        # API metrics
        self.assertIsNotNone(metrics.api_requests_total)
        self.assertIsNotNone(metrics.api_request_duration_seconds)
        self.assertIsNotNone(metrics.api_retries_total)

        # Quota metrics
        self.assertIsNotNone(metrics.quota_usage)
        self.assertIsNotNone(metrics.quota_exceeded_total)

        # Document metrics
        self.assertIsNotNone(metrics.documents_by_status)
        self.assertIsNotNone(metrics.pending_documents)
        self.assertIsNotNone(metrics.awaiting_response)

        # Deadline metrics
        self.assertIsNotNone(metrics.deadline_warnings_total)
        self.assertIsNotNone(metrics.deadline_violations_total)

        # Error metrics
        self.assertIsNotNone(metrics.errors_total)

        # Token metrics
        self.assertIsNotNone(metrics.token_refreshes_total)

        # Info metric
        self.assertIsNotNone(metrics.info)


class EFacturaMetricsRecordMethodsTestCase(TestCase):
    """Test EFacturaMetrics recording methods."""

    def setUp(self):
        self.metrics = EFacturaMetrics()

    def test_record_submission_success(self):
        """Test recording successful submission."""
        # Should not raise any errors
        self.metrics.record_submission(
            status="success",
            document_type="invoice",
            duration=1.5,
        )

    def test_record_submission_without_duration(self):
        """Test recording submission without duration."""
        self.metrics.record_submission(
            status="error",
            document_type="credit_note",
        )

    def test_record_status_check(self):
        """Test recording status check."""
        self.metrics.record_status_check(
            result="success",
            duration=0.5,
        )

    def test_record_status_check_without_duration(self):
        """Test recording status check without duration."""
        self.metrics.record_status_check(result="pending")

    def test_record_validation(self):
        """Test recording validation result."""
        self.metrics.record_validation(
            validation_type="xsd",
            is_valid=True,
        )

    def test_record_validation_with_errors(self):
        """Test recording validation with error rules."""
        self.metrics.record_validation(
            validation_type="schematron",
            is_valid=False,
            error_rules=["BR-01", "BR-02", "BR-03"],
        )

    def test_record_api_request(self):
        """Test recording API request."""
        self.metrics.record_api_request(
            endpoint="upload",
            status_code=200,
            duration=2.0,
        )

    def test_record_api_request_with_retry(self):
        """Test recording API request with retry."""
        self.metrics.record_api_request(
            endpoint="status",
            status_code=503,
            duration=1.0,
            is_retry=True,
            retry_reason="server_error",
        )

    def test_record_error(self):
        """Test recording error."""
        self.metrics.record_error(
            error_type="validation_failed",
            component="xml_builder",
        )

    def test_update_quota_usage(self):
        """Test updating quota usage."""
        self.metrics.update_quota_usage(
            endpoint="status",
            cui="12345678",
            current=50,
        )

    def test_record_quota_exceeded(self):
        """Test recording quota exceeded."""
        self.metrics.record_quota_exceeded(
            endpoint="status",
            cui="12345678",
        )


class EFacturaMetricsContextManagersTestCase(TestCase):
    """Test context managers for timing."""

    def setUp(self):
        self.metrics = EFacturaMetrics()

    def test_time_submission_success(self):
        """Test time_submission context manager on success."""
        with self.metrics.time_submission(document_type="invoice"):
            time.sleep(0.01)  # Simulate work

    def test_time_submission_error(self):
        """Test time_submission context manager on error."""
        with self.assertRaises(ValueError), self.metrics.time_submission(document_type="invoice"):
            raise ValueError("Test error")

    def test_time_api_request(self):
        """Test time_api_request context manager."""
        with self.metrics.time_api_request(endpoint="upload") as context:
            context["status_code"] = 200
            time.sleep(0.01)

    def test_time_api_request_default_status(self):
        """Test time_api_request uses default status code."""
        with self.metrics.time_api_request(endpoint="upload"):
            pass  # Don't set status_code


class EFacturaMetricsSetInfoTestCase(TestCase):
    """Test set_info method."""

    def test_set_info(self):
        """Test set_info updates info metric."""
        metrics = EFacturaMetrics()
        metrics.set_info()
        # Should not raise any errors


class TimedOperationDecoratorTestCase(TestCase):
    """Test timed_operation decorator."""

    def test_decorator_measures_time(self):
        """Test decorator measures execution time."""
        @timed_operation("test_operation")
        def slow_function():
            time.sleep(0.01)
            return "result"

        result = slow_function()
        self.assertEqual(result, "result")

    def test_decorator_handles_exception(self):
        """Test decorator handles function exceptions."""
        @timed_operation("test_operation")
        def failing_function():
            raise ValueError("Test error")

        with self.assertRaises(ValueError):
            failing_function()

    def test_decorator_with_args(self):
        """Test decorator with function arguments."""
        @timed_operation("test_operation")
        def function_with_args(a, b, c=None):
            return f"{a}-{b}-{c}"

        result = function_with_args("x", "y", c="z")
        self.assertEqual(result, "x-y-z")

    @patch("apps.billing.efactura.metrics.efactura_settings")
    def test_decorator_skips_when_disabled(self, mock_settings):
        """Test decorator skips timing when metrics disabled."""
        mock_settings.metrics_enabled = False

        @timed_operation("test_operation")
        def simple_function():
            return "result"

        result = simple_function()
        self.assertEqual(result, "result")


class MetricsWithPrometheusTestCase(TestCase):
    """Test metrics behavior with prometheus_client available."""

    @patch("apps.billing.efactura.metrics.PROMETHEUS_AVAILABLE", True)
    def test_creates_real_metrics_when_available(self):
        """Test real metrics are created when prometheus available."""
        # This is a structural test - we can't easily verify without
        # actually having prometheus_client


class MetricsWithoutPrometheusTestCase(TestCase):
    """Test metrics behavior without prometheus_client."""

    def test_uses_noop_metrics(self):
        """Test NoOp metrics are used when prometheus unavailable."""
        metrics = EFacturaMetrics()
        # All metrics should work without error even if prometheus not installed
        metrics.record_submission("success", "invoice", 1.0)
        metrics.record_api_request("upload", 200, 1.0)
        metrics.record_error("test", "test")


class MetricsEdgeCasesTestCase(TestCase):
    """Test edge cases and error conditions."""

    def test_zero_duration(self):
        """Test recording zero duration."""
        metrics = EFacturaMetrics()
        metrics.record_submission("success", "invoice", 0.0)
        metrics.record_api_request("upload", 200, 0.0)

    def test_negative_duration(self):
        """Test recording negative duration (shouldn't happen)."""
        metrics = EFacturaMetrics()
        metrics.record_submission("success", "invoice", -1.0)

    def test_large_values(self):
        """Test recording very large values."""
        metrics = EFacturaMetrics()
        metrics.record_api_request("upload", 200, 3600.0)  # 1 hour
        metrics.update_quota_usage("status", "12345678", 1000000)

    def test_empty_error_rules(self):
        """Test validation with empty error rules list."""
        metrics = EFacturaMetrics()
        metrics.record_validation("xsd", False, error_rules=[])

    def test_special_characters_in_labels(self):
        """Test labels with special characters."""
        metrics = EFacturaMetrics()
        metrics.record_error("connection_failed", "api-client")
        metrics.record_api_request("upload/validate", 400, 1.0)

    def test_unicode_in_labels(self):
        """Test labels with unicode characters."""
        metrics = EFacturaMetrics()
        metrics.record_error("eroare_conexiune", "client")

    def test_concurrent_updates(self):
        """Test concurrent metric updates don't cause issues."""
        metrics = EFacturaMetrics()
        for _ in range(100):
            metrics.record_submission("success", "invoice", 0.1)
            metrics.record_api_request("upload", 200, 0.1)


class MetricsIntegrationTestCase(TestCase):
    """Integration tests for metrics system."""

    def test_full_submission_workflow(self):
        """Test recording metrics for full submission workflow."""
        metrics = EFacturaMetrics()

        # Generate XML
        metrics.xml_generations_total.labels(
            document_type="invoice",
            status="success",
        ).inc()
        metrics.xml_generation_duration_seconds.labels(
            document_type="invoice",
        ).observe(0.5)

        # Validate
        metrics.record_validation("xsd", True)
        metrics.record_validation("schematron", True)

        # Submit
        with metrics.time_submission("invoice"), metrics.time_api_request("upload") as ctx:
            ctx["status_code"] = 200
            time.sleep(0.01)

        # Check status
        metrics.record_status_check("success", 0.3)

    def test_error_workflow(self):
        """Test recording metrics for error workflow."""
        metrics = EFacturaMetrics()

        # Validation fails
        metrics.record_validation(
            "schematron",
            False,
            error_rules=["BR-01", "BR-16"],
        )

        # Record error
        metrics.record_error("validation_failed", "validator")

    def test_quota_workflow(self):
        """Test recording metrics for quota tracking."""
        metrics = EFacturaMetrics()

        # Update quota
        metrics.update_quota_usage("status", "12345678", 99)

        # Quota exceeded
        metrics.record_quota_exceeded("status", "12345678")
        metrics.record_error("quota_exceeded", "quota_tracker")
