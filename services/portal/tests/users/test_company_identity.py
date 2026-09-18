"""A newly registered company has no tax profile but still has an identity."""

import time
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.users.views import company_profile_view
from tests.dashboard.test_rate_limit_dashboard import _authenticated_request


class NullableTaxProfileContract(SimpleTestCase):
    def test_company_without_tax_profile_keeps_its_name_contact_and_billing_address(self):
        request = _authenticated_request("/company/")
        request.session["user_memberships"] = [{"customer_id": 1, "role": "owner"}]
        request.session["user_memberships_fetched_at"] = time.time()
        company = {"company_name": "New Company SRL", "primary_email": "new@example.com", "tax_profile": None}
        with (
            patch("apps.users.views.api_client.post", return_value={"success": True, "customer": company}),
            patch(
                "apps.users.views.api_client.get_customer_addresses",
                return_value={
                    "success": True,
                    "addresses": [{"is_billing": True, "address_line1": "Str. Nouă 1", "city": "București"}],
                },
            ),
        ):
            response = company_profile_view(request)
        self.assertContains(response, "New Company SRL")
        self.assertContains(response, "new@example.com")
        self.assertContains(response, "Str. Nouă 1")
