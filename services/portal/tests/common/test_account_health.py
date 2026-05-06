"""
Tests for account health banner logic.

Tests the pure functions (evaluate_conditions, blend_banner) directly,
and the orchestrator (get_account_health) with mocked API calls.
"""

import time
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.api_client.services import PlatformAPIError
from apps.common.account_health import (
    AccountCondition,
    blend_banner,
    evaluate_conditions,
    get_account_health,
)


class EvaluateConditionsTest(TestCase):
    """Test evaluate_conditions() — pure function, no mocking needed."""

    def test_all_healthy_returns_empty(self) -> None:
        result = evaluate_conditions(
            invoice_summary={"overdue_invoices": 0},
            services_summary={"suspended_services": 0, "expiring_soon": 0},
            tickets_summary={"waiting_on_customer": 0},
        )
        self.assertEqual(result, [])

    def test_empty_dicts_returns_empty(self) -> None:
        result = evaluate_conditions({}, {}, {})
        self.assertEqual(result, [])

    def test_suspended_services_detected(self) -> None:
        result = evaluate_conditions(
            invoice_summary={},
            services_summary={"suspended_services": 2},
            tickets_summary={},
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].key, "suspended_services")
        self.assertEqual(result[0].severity, "critical")
        self.assertEqual(result[0].count, 2)

    def test_overdue_invoices_detected(self) -> None:
        result = evaluate_conditions(
            invoice_summary={"overdue_invoices": 3},
            services_summary={},
            tickets_summary={},
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].key, "overdue_invoices")
        self.assertEqual(result[0].severity, "critical")
        self.assertEqual(result[0].count, 3)

    def test_expiring_soon_detected(self) -> None:
        result = evaluate_conditions(
            invoice_summary={},
            services_summary={"expiring_soon": 1},
            tickets_summary={},
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].key, "expiring_soon")
        self.assertEqual(result[0].severity, "warning")

    def test_waiting_on_customer_detected(self) -> None:
        result = evaluate_conditions(
            invoice_summary={},
            services_summary={},
            tickets_summary={"waiting_on_customer": 2},
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].key, "waiting_on_customer")
        self.assertEqual(result[0].severity, "info")

    def test_multiple_conditions_sorted_by_priority(self) -> None:
        result = evaluate_conditions(
            invoice_summary={"overdue_invoices": 1},
            services_summary={"suspended_services": 1, "expiring_soon": 2},
            tickets_summary={"waiting_on_customer": 3},
        )
        self.assertEqual(len(result), 4)
        self.assertEqual(result[0].key, "suspended_services")
        self.assertEqual(result[1].key, "overdue_invoices")
        self.assertEqual(result[2].key, "expiring_soon")
        self.assertEqual(result[3].key, "waiting_on_customer")

    def test_zero_values_not_detected(self) -> None:
        """Explicit zeros should not produce conditions."""
        result = evaluate_conditions(
            invoice_summary={"overdue_invoices": 0},
            services_summary={"suspended_services": 0, "expiring_soon": 0},
            tickets_summary={"waiting_on_customer": 0},
        )
        self.assertEqual(result, [])

    def test_string_values_coerced_to_int(self) -> None:
        """API may return string numbers — should still work."""
        result = evaluate_conditions(
            invoice_summary={"overdue_invoices": "2"},
            services_summary={},
            tickets_summary={},
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].count, 2)


class BlendBannerTest(TestCase):
    """Test blend_banner() — pure function."""

    def test_no_conditions_returns_none(self) -> None:
        self.assertIsNone(blend_banner([]))

    def test_single_condition(self) -> None:
        conditions = [
            AccountCondition(
                key="overdue_invoices",
                severity="critical",
                priority=2,
                count=3,
                message="You have 3 overdue invoices.",
                cta_text="View Invoices",
                cta_url="/billing/invoices/?status=overdue",
            ),
        ]
        banner = blend_banner(conditions)
        assert banner is not None
        self.assertEqual(banner.severity, "critical")
        self.assertEqual(banner.message, "You have 3 overdue invoices.")
        self.assertEqual(banner.cta_text, "View Invoices")
        self.assertEqual(banner.condition_count, 1)

    def test_two_conditions_combined(self) -> None:
        conditions = [
            AccountCondition(
                key="suspended_services",
                severity="critical",
                priority=1,
                count=1,
                message="You have 1 suspended service.",
                cta_text="View Services",
                cta_url="/services/?status=suspended",
            ),
            AccountCondition(
                key="overdue_invoices",
                severity="critical",
                priority=2,
                count=2,
                message="You have 2 overdue invoices.",
                cta_text="View Invoices",
                cta_url="/billing/invoices/?status=overdue",
            ),
        ]
        banner = blend_banner(conditions)
        assert banner is not None
        self.assertIn("1 suspended service", banner.message)
        self.assertIn("2 overdue invoices", banner.message)
        self.assertEqual(banner.cta_text, "View Services")  # from highest priority
        self.assertEqual(banner.condition_count, 2)

    def test_three_plus_conditions_shows_remaining_count(self) -> None:
        conditions = [
            AccountCondition("a", "critical", 1, 1, "Issue A.", "CTA A", "/a"),
            AccountCondition("b", "critical", 2, 2, "Issue B.", "CTA B", "/b"),
            AccountCondition("c", "warning", 3, 3, "Issue C.", "CTA C", "/c"),
        ]
        banner = blend_banner(conditions)
        assert banner is not None
        self.assertIn("Issue A.", banner.message)
        self.assertIn("Issue B.", banner.message)
        self.assertIn("1 more issue", banner.message)
        self.assertEqual(banner.cta_text, "CTA A")
        self.assertEqual(banner.condition_count, 3)

    def test_severity_escalation(self) -> None:
        """Banner severity should be the highest among conditions."""
        conditions = [
            AccountCondition("a", "info", 4, 1, "Info.", "CTA", "/a"),
            AccountCondition("b", "warning", 3, 1, "Warning.", "CTA", "/b"),
        ]
        banner = blend_banner(conditions)
        assert banner is not None
        self.assertEqual(banner.severity, "warning")

    def test_critical_overrides_warning_and_info(self) -> None:
        conditions = [
            AccountCondition("a", "info", 4, 1, "Info.", "CTA", "/a"),
            AccountCondition("b", "critical", 1, 1, "Critical.", "CTA", "/b"),
        ]
        banner = blend_banner(conditions)
        assert banner is not None
        self.assertEqual(banner.severity, "critical")


class GetAccountHealthTest(TestCase):
    """Test get_account_health() orchestrator with mocked API calls."""

    @staticmethod
    def _make_request(session_data: dict | None = None) -> MagicMock:
        """Create a mock request with session data.

        Also pre-populates ``request.customer_id`` from the session
        (mirroring what ``apps.users.middleware`` does on every
        authenticated request) so tests that don't care about the
        request.customer_id vs session['customer_id'] divergence keep
        working without explicit setup.
        """
        request = MagicMock()
        session = session_data if session_data is not None else {}
        request.session = session
        cid = session.get("customer_id")
        request.customer_id = int(cid) if cid is not None else None
        return request

    def test_unauthenticated_returns_none(self) -> None:
        request = self._make_request({})
        self.assertIsNone(get_account_health(request))

    def test_no_user_id_returns_none(self) -> None:
        request = self._make_request({"customer_id": "1"})
        self.assertIsNone(get_account_health(request))

    @patch("apps.common.account_health._fetch_summaries")
    def test_fetches_and_caches_on_first_call(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = (
            {"overdue_invoices": 2},
            {"suspended_services": 0, "expiring_soon": 0},
            {"waiting_on_customer": 0},
            True,  # all_succeeded
        )
        session: dict = {"customer_id": "1", "user_id": "10"}
        request = self._make_request(session)

        banner = get_account_health(request)

        mock_fetch.assert_called_once_with(1, 10)
        assert banner is not None
        self.assertEqual(banner.severity, "critical")
        # Verify session was populated
        self.assertIn("account_health_data", session)
        self.assertIn("account_health_fetched_at", session)

    @patch("apps.common.account_health._fetch_summaries")
    def test_uses_request_customer_id_not_legacy_session_key(self, mock_fetch: MagicMock) -> None:
        """get_account_health must source the active customer from
        request.customer_id (set by middleware after company switch),
        not from the stale legacy request.session['customer_id'].

        Regression of PR #164 review finding H4: middleware updates
        request.customer_id when the user switches customers, but
        request.session['customer_id'] keeps the original login customer.
        Reading the legacy key meant get_account_health silently fetched
        for the wrong customer after a switch.
        """
        mock_fetch.return_value = ({}, {}, {}, True)
        # Session still has the *original* login customer; middleware has
        # since updated request.customer_id to reflect the active selection.
        session: dict = {"customer_id": "1", "user_id": "10"}
        request = self._make_request(session)
        request.customer_id = 2  # Active customer after switch

        get_account_health(request)

        # Must fetch for the ACTIVE customer, not the legacy session value.
        mock_fetch.assert_called_once_with(2, 10)

    @patch("apps.common.account_health._fetch_summaries")
    def test_returns_none_when_request_customer_id_absent(self, mock_fetch: MagicMock) -> None:
        """If middleware did not set request.customer_id (e.g., unauthenticated
        request hit a path that calls get_account_health), return None
        rather than fetching for a stale session key."""
        session: dict = {"user_id": "10"}  # No legacy customer_id either
        request = self._make_request(session)
        # request.customer_id is already None because session lacks customer_id
        request.customer_id = None

        result = get_account_health(request)

        self.assertIsNone(result)
        mock_fetch.assert_not_called()

    @patch("apps.common.account_health.TicketsAPIClient")
    @patch("apps.common.account_health.ServicesAPIClient")
    @patch("apps.common.account_health.InvoiceViewService")
    def test_does_not_seed_cache_when_invoice_summary_fails(
        self, mock_invoice_cls, mock_services_cls, mock_tickets_cls,
    ) -> None:
        """If any underlying summary fetch fails, the session cache must
        NOT be populated. Otherwise the empty fallback (e.g., overdue=0)
        gets cached for ACCOUNT_HEALTH_CACHE_TTL and silently suppresses
        the banner that should have been shown.

        Regression of PR #164 review finding H2b: _fetch_summaries
        previously returned safe defaults on per-summary failure, then
        the orchestrator unconditionally wrote them to session cache.
        """
        mock_invoice_cls.return_value.get_invoice_summary.side_effect = PlatformAPIError(
            "platform down", status_code=500, is_rate_limited=False,
        )
        mock_services_cls.return_value.get_services_summary.return_value = {"active_services": 1}
        mock_tickets_cls.return_value.get_tickets_summary.return_value = {"waiting_on_customer": 0}

        session: dict = {"customer_id": "1", "user_id": "10"}
        request = self._make_request(session)

        get_account_health(request)

        self.assertNotIn("account_health_data", session)
        self.assertNotIn("account_health_fetched_at", session)

    @patch("apps.common.account_health.TicketsAPIClient")
    @patch("apps.common.account_health.ServicesAPIClient")
    @patch("apps.common.account_health.InvoiceViewService")
    def test_does_not_seed_cache_when_services_summary_fails(
        self, mock_invoice_cls, mock_services_cls, mock_tickets_cls,
    ) -> None:
        """Services-side failure must also block cache seeding."""
        mock_invoice_cls.return_value.get_invoice_summary.return_value = {"overdue_invoices": 0}
        mock_services_cls.return_value.get_services_summary.side_effect = PlatformAPIError(
            "platform down", status_code=500, is_rate_limited=False,
        )
        mock_tickets_cls.return_value.get_tickets_summary.return_value = {"waiting_on_customer": 0}

        session: dict = {"customer_id": "1", "user_id": "10"}
        request = self._make_request(session)

        get_account_health(request)

        self.assertNotIn("account_health_data", session)

    @patch("apps.common.account_health._fetch_summaries")
    def test_uses_cache_when_fresh(self, mock_fetch: MagicMock) -> None:
        session: dict = {
            "customer_id": "1",
            "user_id": "10",
            "account_health_data": {
                "invoice": {"overdue_invoices": 1},
                "services": {},
                "tickets": {},
            },
            "account_health_fetched_at": time.time(),  # Fresh
        }
        request = self._make_request(session)

        banner = get_account_health(request)

        mock_fetch.assert_not_called()
        assert banner is not None
        self.assertEqual(banner.severity, "critical")

    @patch("apps.common.account_health._fetch_summaries")
    def test_refetches_when_cache_expired(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = ({}, {}, {}, True)
        session: dict = {
            "customer_id": "1",
            "user_id": "10",
            "account_health_data": {
                "invoice": {"overdue_invoices": 1},
                "services": {},
                "tickets": {},
            },
            "account_health_fetched_at": time.time() - 600,  # Expired (> 300s TTL)
        }
        request = self._make_request(session)

        banner = get_account_health(request)

        mock_fetch.assert_called_once()
        self.assertIsNone(banner)  # Fresh fetch returned all zeros

    @patch("apps.common.account_health._fetch_summaries")
    def test_api_error_returns_none_no_false_positives(self, mock_fetch: MagicMock) -> None:
        """On API failure, defaults should be empty → no banner shown."""
        mock_fetch.return_value = ({}, {}, {}, False)
        session: dict = {"customer_id": "1", "user_id": "10"}
        request = self._make_request(session)

        banner = get_account_health(request)

        self.assertIsNone(banner)

    @patch("apps.common.account_health._fetch_summaries")
    def test_healthy_account_returns_none(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = (
            {"overdue_invoices": 0},
            {"suspended_services": 0, "expiring_soon": 0},
            {"waiting_on_customer": 0},
            True,
        )
        session: dict = {"customer_id": "1", "user_id": "10"}
        request = self._make_request(session)

        self.assertIsNone(get_account_health(request))
