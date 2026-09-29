"""The Portal retains currency groups and treats missing money as unavailable."""

import json
import time
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase, override_settings

from apps.billing.services import InvoiceViewService
from apps.billing.views import billing_dashboard_widget
from apps.dashboard.views import dashboard_view
from tests.dashboard.test_rate_limit_dashboard import _authenticated_request


def summary_payload() -> dict:
    return {
        "total_invoices": 3, "draft_invoices": 0, "issued_invoices": 2, "overdue_invoices": 1,
        "paid_invoices": 0, "total_amount_due_cents": None, "currency_code": None,
        "amount_due_by_currency": {"EUR": 9200, "RON": 5000, "USD": 9000},
        "credit_balance_by_currency": {"EUR": 2000}, "spendable_credit_by_currency": {"EUR": 0},
        "held_credit_entries": [{"id": 7, "delta_cents": -1000, "reason": "Old use",
                                 "currency_hold_reason": "No immutable source identifies the original currency"}],
        "credit_spending_on_hold": True, "recent_invoices": [],
    }


@override_settings(LANGUAGE_CODE="en")
class BillingSummaryCurrencyTests(SimpleTestCase):
    def _service_summary(self, payload: dict | None = None) -> dict:
        with patch("apps.billing.services.PlatformAPIClient.post", return_value={
            "success": True, "summary": summary_payload() if payload is None else payload,
        }):
            return InvoiceViewService().get_invoice_summary(1, 1)

    def test_service_preserves_currency_groups_and_held_entries(self) -> None:
        summary = self._service_summary()

        self.assertEqual(summary["amount_due_by_currency"], {"EUR": 9200, "RON": 5000, "USD": 9000})
        self.assertIsNone(summary["total_amount_due"])
        self.assertIsNone(summary["currency_code"])
        self.assertEqual(summary["credit_balance_by_currency"], {"EUR": 2000})
        self.assertEqual(summary["spendable_credit_by_currency"], {"EUR": 0})
        self.assertEqual(summary["held_credit_entries"][0]["delta_cents"], -1000)

    def test_legacy_single_currency_response_preserves_its_explicit_currency(self) -> None:
        payload = summary_payload()
        payload.pop("amount_due_by_currency")
        payload.update(total_amount_due_cents=1234, currency_code="USD")

        summary = self._service_summary(payload)

        self.assertEqual(summary["amount_due_by_currency"], {"USD": 1234})
        self.assertEqual(summary["total_amount_due"], 1234)
        self.assertEqual(summary["currency_code"], "USD")

    def test_missing_currency_and_malformed_amounts_are_unavailable_not_zero_ron(self) -> None:
        for amounts in ({"": 9200}, {"EUR": "bad"}, {"EUR": None}, {"EUR": True}):
            with self.subTest(amounts=amounts):
                payload = summary_payload()
                payload["amount_due_by_currency"] = amounts

                summary = self._service_summary(payload)

                self.assertFalse(summary["summary_available"])
                self.assertIsNone(summary["total_amount_due"])
                self.assertEqual(summary["amount_due_by_currency"], {})

    def test_legacy_money_without_a_currency_is_unavailable(self) -> None:
        payload = summary_payload()
        payload.pop("amount_due_by_currency")
        payload.update(total_amount_due_cents=1234, currency_code=None)

        summary = self._service_summary(payload)

        self.assertFalse(summary["summary_available"])
        self.assertIsNone(summary["currency_code"])

    def test_contradictory_spendable_credit_is_unavailable(self) -> None:
        payload = summary_payload()
        payload["spendable_credit_by_currency"] = {"EUR": 2000}

        summary = self._service_summary(payload)

        self.assertFalse(summary["summary_available"])

    def test_widget_does_not_emit_a_mixed_scalar_or_ron_label(self) -> None:
        request = _authenticated_request("/billing/dashboard-widget/")
        request.session["user_memberships"] = [{"customer_id": "1", "role": "owner"}]
        request.session["user_memberships_fetched_at"] = time.time()
        with patch("apps.billing.services.PlatformAPIClient.post", return_value={
            "success": True, "summary": summary_payload(),
        }):
            response = billing_dashboard_widget(request)

        self.assertEqual(response.status_code, 200)
        summary = json.loads(response.content)["summary"]
        self.assertEqual(summary["amount_due_by_currency"], {"EUR": 9200, "RON": 5000, "USD": 9000})
        self.assertIsNone(summary["total_due_cents"])
        self.assertIsNone(summary["total_due_formatted"])

    def test_dashboard_renders_separate_due_and_credit_amounts_and_explicit_currency_hold(self) -> None:
        with (
            patch("apps.dashboard.views._get_billing_data", return_value=([], self._service_summary())),
            patch("apps.dashboard.views._get_services_data", return_value=(0, {})),
            patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {})),
            patch("apps.dashboard.views._get_customer_data", return_value=([], None)),
        ):
            response = dashboard_view(_authenticated_request())

        for amount in ("92,00 EUR", "50,00 RON", "90,00 USD", "20,00 EUR", "0,00 EUR"):
            self.assertContains(response, amount)
        self.assertContains(response, "Currency unavailable")
        self.assertContains(response, "Credit spending is on hold")
        self.assertNotContains(response, "232,00 RON")

    def test_unavailable_summary_does_not_claim_zero_debt_or_credit(self) -> None:
        html = render_to_string(
            "billing/partials/currency_balances.html", {"billing_summary": InvoiceViewService()._empty_summary()}
        )
        self.assertIn("Billing balances are temporarily unavailable", html)
        self.assertNotIn("0,00 RON", html)

    def test_unavailable_summary_is_not_cached_as_a_healthy_account(self) -> None:
        request = _authenticated_request()
        with (
            patch("apps.dashboard.views._get_billing_data", return_value=([], InvoiceViewService._empty_summary())),
            patch("apps.dashboard.views._get_services_data", return_value=(1, {"active_services": 1})),
            patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {"open_tickets": 0})),
            patch("apps.dashboard.views._get_customer_data", return_value=([], None)),
        ):
            dashboard_view(request)

        self.assertNotIn("account_health_data", request.session)
