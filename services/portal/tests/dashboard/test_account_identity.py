"""Dashboard and account information come from the selected customer's API data."""

from types import SimpleNamespace
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase

from apps.dashboard.views import account_overview_view
from tests.dashboard.test_rate_limit_dashboard import _authenticated_request


class AccountIdentityContracts(SimpleTestCase):
    def test_non_active_and_unknown_customer_status_is_not_hardcoded_active(self):
        for status, expected in (
            ("active", "Active"),
            ("suspended", "Suspended"),
            ("inactive", "Inactive"),
            (None, "Unavailable"),
        ):
            customer = SimpleNamespace(status=status, name="Account owner", company_name="Account owner")
            html = render_to_string("dashboard/dashboard.html", {"dashboard_data": {"customers": [customer]}})
            self.assertIn(expected, html)
            # The rendered stat value is separate from the unrelated Active Services label.
            if status != "active":
                self.assertNotIn(">Active<", html)

    def test_account_overview_unwraps_the_customer_and_tax_profile(self):
        customer = {"id": 1, "company_name": "Știință SRL", "tax_profile": {"cui": "RO14399847"}}
        with patch(
            "apps.dashboard.views.api_client.get_customer_details", return_value={"success": True, "customer": customer}
        ):
            response = account_overview_view(_authenticated_request("/dashboard/account/"))
        self.assertContains(response, "Știință SRL")
        self.assertContains(response, "RO14399847")
