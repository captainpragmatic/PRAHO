"""
Tests that customer-context switches invalidate the account_health
session cache so the banner reflects the newly-active customer
(PR #164 review finding H3).
"""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, SimpleTestCase

from apps.users.views import create_company_view, switch_customer_view


def _authenticated_request(method: str, path: str, post_data: dict | None = None) -> object:
    factory = RequestFactory()
    request = factory.post(path, data=post_data or {}) if method == "POST" else factory.get(path)
    SessionMiddleware(lambda r: None).process_request(request)
    request.session["user_id"] = 1
    request.session["customer_id"] = "1"
    request.session["email"] = "test@example.com"
    request._messages = FallbackStorage(request)
    # @csrf_protect would otherwise reject the POST in tests.
    request._dont_enforce_csrf_checks = True
    return request


def _seed_health_cache(request) -> None:
    """Pre-populate the account-health session cache so we can detect
    whether the view-under-test invalidates it."""
    request.session["account_health_data"] = {
        "invoice": {"overdue_invoices": 5},
        "services": {"suspended_services": 1},
        "tickets": {"waiting_on_customer": 0},
    }
    request.session["account_health_fetched_at"] = 1700000000.0


class SwitchCustomerCacheInvalidationTests(SimpleTestCase):
    """switch_customer_view must clear account_health_data and
    account_health_fetched_at so the banner reflects the newly-active
    customer instead of the previous one for up to 5 minutes."""

    @patch("apps.users.views._get_user_customer_memberships")
    @patch("apps.users.views.api_client.post")
    def test_switch_customer_pops_account_health_cache(
        self, mock_api_post, mock_memberships,
    ) -> None:
        # Platform API approves the switch.
        mock_api_post.return_value = {
            "success": True,
            "data": {
                "has_access": True,
                "customer_name": "New Customer SRL",
                "role": "owner",
            },
        }
        mock_memberships.return_value = [
            {"customer_id": "2", "customer_name": "New Customer SRL", "role": "owner"},
        ]

        request = _authenticated_request("POST", "/auth/switch-customer/", post_data={"customer_id": "2"})
        _seed_health_cache(request)

        # Sanity: cache exists before switch.
        self.assertIn("account_health_data", request.session)
        self.assertIn("account_health_fetched_at", request.session)

        switch_customer_view(request)

        self.assertNotIn(
            "account_health_data", request.session,
            msg="switch_customer_view must invalidate account_health_data so the "
                "banner refetches for the new customer (H3a).",
        )
        self.assertNotIn(
            "account_health_fetched_at", request.session,
            msg="switch_customer_view must invalidate account_health_fetched_at "
                "alongside the data key (H3a).",
        )


class CreateCompanyCacheInvalidationTests(SimpleTestCase):
    """create_company_view auto-selects the new company; the
    account-health cache must be invalidated so the banner reflects
    the freshly-created (and empty) account state."""

    @patch("apps.users.views.CompanyCreationForm")
    @patch("apps.users.views.api_client.post")
    def test_create_company_pops_account_health_cache(
        self, mock_api_post, mock_form_cls,
    ) -> None:
        # Bypass form validation by stubbing the form class — this test is
        # specifically about the cache-invalidation contract, not form
        # field semantics (which are covered by dedicated form tests).
        mock_form = mock_form_cls.return_value
        mock_form.is_valid.return_value = True
        mock_form.cleaned_data = {
            "company_name": "Brand New SRL",
            "vat_number": "",
            "trade_registry_number": "",
            "industry": "",
            "street_address": "Str. Test 1",
            "city": "Bucharest",
            "state": "",
            "postal_code": "012345",
            "country": "România",
            "primary_email": "owner@new.ro",
            "primary_phone": "+40712345678",
            "website": "",
        }
        mock_api_post.return_value = {
            "success": True,
            "customer_id": 99,
        }

        request = _authenticated_request("POST", "/auth/company/create/", post_data={})
        _seed_health_cache(request)

        self.assertIn("account_health_data", request.session)

        create_company_view(request)

        self.assertNotIn(
            "account_health_data", request.session,
            msg="create_company_view must invalidate account_health_data when "
                "auto-switching to the new company (H3b).",
        )
        self.assertNotIn(
            "account_health_fetched_at", request.session,
            msg="create_company_view must invalidate account_health_fetched_at "
                "alongside the data key (H3b).",
        )
