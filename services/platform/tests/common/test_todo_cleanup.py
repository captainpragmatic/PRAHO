"""
Tests verifying all stale TODO comments have been removed.

Covers T2 (ClamAV), T3 (monitoring), I1 (Stripe webhook), S1 (settings),
O3 (orders RefundService comment), and all other fixed TODOs.
"""

import os

from django.test import TestCase

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(relative_path: str) -> str:
    with open(os.path.join(BASE_DIR, relative_path)) as f:
        return f.read()


class StaleTodoCleanupTests(TestCase):
    """Verify all targeted TODO comments have been removed from source"""

    def test_tickets_security_no_todo(self):
        """tickets/security.py: ClamAV TODO replaced"""
        self.assertNotIn("TODO", _read("apps/tickets/security.py"))

    def test_tickets_monitoring_no_todo(self):
        """tickets/monitoring.py: external monitoring TODO replaced"""
        self.assertNotIn("TODO", _read("apps/tickets/monitoring.py"))

    def test_stripe_webhook_no_todo(self):
        """integrations/webhooks/stripe.py: HTTP client TODO removed"""
        self.assertNotIn("TODO", _read("apps/integrations/webhooks/stripe.py"))

    def test_setup_settings_no_todo(self):
        """settings command: help text TODO removed"""
        self.assertNotIn("TODO", _read("apps/settings/management/commands/setup_default_settings.py"))

    def test_orders_views_no_todo(self):
        """orders/views.py: RefundService and edit TODOs removed"""
        self.assertNotIn("TODO", _read("apps/orders/views.py"))

    def test_tickets_views_no_todo(self):
        """tickets/views.py: file security TODO removed"""
        self.assertNotIn("TODO", _read("apps/tickets/views.py"))

    def test_users_services_no_todo(self):
        """users/services.py: county auto-detect TODO removed"""
        self.assertNotIn("TODO", _read("apps/users/services.py"))

    def test_api_tickets_views_no_todo(self):
        """api/tickets/views.py: SQLite TODOs removed"""
        self.assertNotIn("TODO", _read("apps/api/tickets/views.py"))

    def test_api_customers_views_no_todo(self):
        """api/customers/views.py: service management TODO removed"""
        self.assertNotIn("TODO", _read("apps/api/customers/views.py"))
