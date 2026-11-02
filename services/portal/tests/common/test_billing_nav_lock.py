"""The Billing menu item shows as unavailable to members the billing pages would refuse.

It showed to every member, but the billing views are owner/billing only (require_billing_access), so tech and viewer
members got a 403. The menu reads the role from the session's cached memberships (no API call per page): a known role
outside owner/billing locks it with the reason; an unknown role leaves it alone, and the view still decides.
"""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.sessions.middleware import SessionMiddleware
from django.test import SimpleTestCase
from django.test.client import RequestFactory

from apps.common.context_processors import portal_context

REASON = "Only owners and billing members can open billing."


def _request(role: str | None):
    request = RequestFactory().get("/dashboard/")
    SessionMiddleware(lambda r: None).process_request(request)
    request.session["customer_id"] = "7"
    request.session["user_id"] = "9"
    if role is not None:
        request.session["user_memberships"] = [{"customer_id": 7, "role": role}]
    return request


@patch("apps.common.context_processors.get_account_health", return_value=None)
class BillingNavLockTests(SimpleTestCase):
    def test_tech_and_viewer_members_see_billing_locked_with_why(self, _health) -> None:
        for role in ("tech", "viewer"):
            with self.subTest(role=role):
                self.assertEqual(str(portal_context(_request(role))["billing_nav_locked"]), REASON)

    def test_owner_billing_and_an_unknown_role_keep_the_link(self, _health) -> None:
        for role in ("owner", "billing", None):
            with self.subTest(role=role):
                self.assertFalse(portal_context(_request(role)).get("billing_nav_locked"))

    def test_both_menus_render_the_lock_instead_of_the_link(self, _health) -> None:
        from django.template.loader import render_to_string  # noqa: PLC0415

        for mobile in (False, True):
            with self.subTest(mobile=mobile):
                locked = render_to_string(
                    "components/billing_nav_item.html", {"billing_nav_locked": REASON, "mobile": mobile}
                )
                self.assertNotIn('href="/billing/invoices/"', locked)
                self.assertIn(REASON, locked)
                open_ = render_to_string(
                    "components/billing_nav_item.html", {"billing_nav_locked": "", "mobile": mobile}
                )
                self.assertIn('href="/billing/invoices/"', open_)

    def test_the_nav_rule_is_the_views_rule(self, _health) -> None:
        from apps.common.decorators import BILLING_ROLES  # noqa: PLC0415

        self.assertEqual(set(BILLING_ROLES), {"owner", "billing"})


@patch("apps.common.context_processors.get_account_health", return_value=None)
class BillingNavFollowsTheSelectedCompanyTests(SimpleTestCase):
    """A member switches companies: the menu reads the company the billing views will check, not the login one."""

    def test_owner_of_the_selected_company_keeps_billing(self, _health) -> None:
        request = _request(None)
        request.session["user_memberships"] = [{"customer_id": 7, "role": "tech"}, {"customer_id": 8, "role": "owner"}]
        request.session["selected_customer_id"] = "8"
        self.assertFalse(portal_context(request).get("billing_nav_locked"))
        request.session["selected_customer_id"] = "7"
        self.assertEqual(str(portal_context(request)["billing_nav_locked"]), REASON)
