"""
Tests for e-Factura task scheduling wired in BillingConfig.ready().
"""

from unittest.mock import patch

from django.test import TestCase, override_settings


class BillingConfigReadyTestCase(TestCase):
    """Test that BillingConfig.ready() schedules e-Factura tasks correctly."""

    @override_settings(EFACTURA_ENABLED=True)
    @patch("apps.billing.efactura.tasks.schedule_efactura_tasks")
    def test_schedules_tasks_when_efactura_enabled(self, mock_schedule):
        """Tasks should be scheduled when EFACTURA_ENABLED=True."""
        from apps.billing.apps import BillingConfig

        config = BillingConfig("apps.billing", __import__("apps.billing"))
        config.ready()

        mock_schedule.assert_called_once()

    @override_settings(EFACTURA_ENABLED=False)
    @patch("apps.billing.efactura.tasks.schedule_efactura_tasks")
    def test_skips_scheduling_when_efactura_disabled(self, mock_schedule):
        """Tasks should NOT be scheduled when EFACTURA_ENABLED=False."""
        from apps.billing.apps import BillingConfig

        config = BillingConfig("apps.billing", __import__("apps.billing"))
        config.ready()

        mock_schedule.assert_not_called()

    @override_settings(EFACTURA_ENABLED=True)
    @patch(
        "apps.billing.efactura.tasks.schedule_efactura_tasks",
        side_effect=Exception("DB not ready"),
    )
    def test_handles_scheduling_failure_gracefully(self, mock_schedule):
        """Startup should not crash if scheduling fails."""
        from apps.billing.apps import BillingConfig

        config = BillingConfig("apps.billing", __import__("apps.billing"))
        # Should not raise
        config.ready()
