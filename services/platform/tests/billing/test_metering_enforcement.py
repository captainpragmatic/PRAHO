# ===============================================================================
# METERING THRESHOLD ENFORCEMENT TESTS
# ===============================================================================
"""Tests for _take_threshold_action in UsageAlertService."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import TestCase

from apps.billing.metering_service import UsageAlertService


def _make_alert(customer_id="test-customer-123"):
    """Create a mock alert with a mock customer."""
    alert = MagicMock()
    alert.customer = MagicMock()
    alert.customer.id = customer_id
    alert.customer.__str__ = lambda self: f"Customer({customer_id})"
    alert.id = "alert-001"
    return alert


class ThrottleActionTestCase(TestCase):
    """Test throttle action calls provisioning suspend."""

    @patch("apps.billing.metering_service.AuditService")
    @patch("apps.provisioning.provisioning_service.ProvisioningService.suspend_services_for_customer")
    def test_throttle_calls_provisioning_suspend(self, mock_suspend, mock_audit):
        alert = _make_alert()
        service = UsageAlertService()

        service._take_threshold_action(alert, "throttle")

        mock_suspend.assert_called_once_with(customer_id=alert.customer.id, reason="usage_throttled")


class SuspendActionTestCase(TestCase):
    """Test suspend action calls provisioning suspend with correct reason."""

    @patch("apps.billing.metering_service.AuditService")
    @patch("apps.provisioning.provisioning_service.ProvisioningService.suspend_services_for_customer")
    def test_suspend_calls_provisioning_suspend(self, mock_suspend, mock_audit):
        alert = _make_alert()
        service = UsageAlertService()

        service._take_threshold_action(alert, "suspend")

        mock_suspend.assert_called_once_with(customer_id=alert.customer.id, reason="usage_exceeded")


class BlockNewActionTestCase(TestCase):
    """Test block_new action sets cache flag."""

    @patch("apps.billing.metering_service.AuditService")
    def test_block_new_sets_cache_flag(self, mock_audit):
        alert = _make_alert(customer_id="cust-block-test")
        service = UsageAlertService()

        service._take_threshold_action(alert, "block_new")

        cache_key = f"usage_blocked:{alert.customer.id}"
        self.assertTrue(cache.get(cache_key))

    def tearDown(self):
        cache.clear()


class WarnActionTestCase(TestCase):
    """Test warn action has no provisioning or cache side effects."""

    @patch("apps.provisioning.provisioning_service.ProvisioningService.suspend_services_for_customer")
    def test_warn_action_no_side_effects(self, mock_suspend):
        alert = _make_alert(customer_id="cust-warn-test")
        service = UsageAlertService()

        service._take_threshold_action(alert, "warn")

        mock_suspend.assert_not_called()
        cache_key = f"usage_blocked:{alert.customer.id}"
        self.assertIsNone(cache.get(cache_key))


class EnforcementAuditLoggingTestCase(TestCase):
    """Test that enforcement actions log audit events."""

    @patch("apps.billing.metering_service.AuditService")
    @patch("apps.provisioning.provisioning_service.ProvisioningService.suspend_services_for_customer")
    def test_throttle_logs_audit_event(self, mock_suspend, mock_audit):
        alert = _make_alert()
        service = UsageAlertService()

        service._take_threshold_action(alert, "throttle")

        mock_audit.log_simple_event.assert_called_once()
        call_kwargs = mock_audit.log_simple_event.call_args
        self.assertEqual(call_kwargs.kwargs["event_type"], "metering_throttle_applied")

    @patch("apps.billing.metering_service.AuditService")
    @patch("apps.provisioning.provisioning_service.ProvisioningService.suspend_services_for_customer")
    def test_suspend_logs_audit_event(self, mock_suspend, mock_audit):
        alert = _make_alert()
        service = UsageAlertService()

        service._take_threshold_action(alert, "suspend")

        mock_audit.log_simple_event.assert_called_once()
        call_kwargs = mock_audit.log_simple_event.call_args
        self.assertEqual(call_kwargs.kwargs["event_type"], "metering_suspension_applied")

    @patch("apps.billing.metering_service.AuditService")
    def test_block_new_logs_audit_event(self, mock_audit):
        alert = _make_alert()
        service = UsageAlertService()

        service._take_threshold_action(alert, "block_new")

        mock_audit.log_simple_event.assert_called_once()
        call_kwargs = mock_audit.log_simple_event.call_args
        self.assertEqual(call_kwargs.kwargs["event_type"], "metering_new_usage_blocked")

    def tearDown(self):
        cache.clear()
