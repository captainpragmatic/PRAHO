"""Withdraw authorization and toggle auto-payment: two endpoints with no test at all.

Both are POST-only JSON views that proxy to `RecurringPaymentsService`, returning the
service's own `{"success": bool, ...}` shape verbatim. A status-only test here would not
even catch the view forwarding the wrong keyword to the wrong service method - the JSON
body is the only place the actual outcome is visible.
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse


class RecurringAuthorizationWithdrawTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.billing.views.RecurringPaymentsService.withdraw_authorization")
    def test_a_successful_withdrawal_reports_success_in_the_body(self, withdraw) -> None:
        withdraw.return_value = {"success": True}

        response = self.client.post(
            reverse("billing:recurring_authorization_withdraw"),
            data=json.dumps({"authorization_id": "auth-123"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {"success": True})
        withdraw.assert_called_once_with(customer_id=42, user_id=7, authorization_id="auth-123")

    @patch("apps.billing.views.RecurringPaymentsService.withdraw_authorization")
    def test_a_platform_refusal_is_reported_as_a_400_with_its_own_error(self, withdraw) -> None:
        """The view maps a falsy `success` to 400 - a status-only check could not tell this
        apart from the 400 a missing authorization_id also produces."""
        withdraw.return_value = {"success": False, "error": "Authorization already withdrawn"}

        response = self.client.post(
            reverse("billing:recurring_authorization_withdraw"),
            data=json.dumps({"authorization_id": "auth-123"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "Authorization already withdrawn")

    def test_a_missing_authorization_id_is_forwarded_empty_and_the_service_rejects_it(self) -> None:
        with patch("apps.billing.views.RecurringPaymentsService.withdraw_authorization") as withdraw:
            withdraw.return_value = {"success": False, "error": "Authorization not found"}
            response = self.client.post(
                reverse("billing:recurring_authorization_withdraw"),
                data=json.dumps({}),
                content_type="application/json",
            )

        # The view still calls through with an empty string - it is the SERVICE's job to refuse an
        # empty authorization_id, and this pins that the view does not silently swallow the omission.
        withdraw.assert_called_once_with(customer_id=42, user_id=7, authorization_id="")
        self.assertEqual(response.status_code, 400)

    def test_get_is_rejected(self) -> None:
        response = self.client.get(reverse("billing:recurring_authorization_withdraw"))
        self.assertEqual(response.status_code, 405)


class SubscriptionAutoPaymentToggleTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.billing.views.RecurringPaymentsService.set_subscription_auto_payment")
    def test_enabling_auto_payment_passes_the_boolean_through_unmodified(self, set_toggle) -> None:
        set_toggle.return_value = {"success": True, "auto_payment_enabled": True}

        response = self.client.post(
            reverse("billing:subscription_auto_payment"),
            data=json.dumps({"subscription_id": "sub-1", "authorization_id": "auth-1", "enabled": True}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {"success": True, "auto_payment_enabled": True})
        set_toggle.assert_called_once_with(
            customer_id=42, user_id=7, subscription_id="sub-1", authorization_id="auth-1", enabled=True
        )

    @patch("apps.billing.views.RecurringPaymentsService.set_subscription_auto_payment")
    def test_disabling_clears_the_authorization_reference(self, set_toggle) -> None:
        set_toggle.return_value = {"success": True, "auto_payment_enabled": False}

        response = self.client.post(
            reverse("billing:subscription_auto_payment"),
            data=json.dumps({"subscription_id": "sub-1", "authorization_id": None, "enabled": False}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        set_toggle.assert_called_once_with(
            customer_id=42, user_id=7, subscription_id="sub-1", authorization_id=None, enabled=False
        )

    def test_a_non_boolean_enabled_flag_is_rejected_with_a_400(self) -> None:
        """`isinstance(data.get("enabled"), bool)` is the view's own guard - a string "true" must
        not silently coerce to the boolean the service expects."""
        with patch("apps.billing.views.RecurringPaymentsService.set_subscription_auto_payment") as set_toggle:
            response = self.client.post(
                reverse("billing:subscription_auto_payment"),
                data=json.dumps({"subscription_id": "sub-1", "enabled": "true"}),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content), {"success": False, "error": "Invalid request"})
        set_toggle.assert_not_called()
