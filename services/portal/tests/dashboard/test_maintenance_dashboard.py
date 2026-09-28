"""A maintenance window must not be rendered as a dashboard full of zeros.

`dashboard_view` has a per-section degradation model with exactly ONE degraded state: rate limited.
So a maintenance 503 was logged at ERROR level, as though it were a fault of ours, and then flattened
into the zero shape - which the stat tiles rendered as "0" and the lists as "No recent documents
found". A customer in a window saw a dashboard stating, in numbers, that they had nothing.

It is two layers, and both had to be found. The `_get_*_data` helpers re-raise only a throttle, so a
window never even reached the view's per-section handler; and that handler classifies only a throttle,
so even a propagated window would have produced no signal for the template to read.

Deliberately NOT done by widening `sections_rate_limited` to mean "degraded". A flag that decides both
whether the state is surfaced AND what the customer is told is how a 503 came to announce "scheduled
maintenance - your data is safe" during real failures. `sections_unavailable` is a parallel set:
whether it is surfaced is one decision, what it is called is another.

Mirrors `test_rate_limit_dashboard.py`, which is the same shape for the state that already worked.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import SimpleTestCase, override_settings
from django.test.client import RequestFactory

from apps.api_client.services import PlatformAPIError
from apps.dashboard.views import _get_services_data, dashboard_view


def _maintenance_error(retry_after: int = 600) -> PlatformAPIError:
    """A 503 the platform's own gate MARKED. A bare 503 is not enough - see `PlatformAPIError`."""
    return PlatformAPIError(
        "unavailable", status_code=503, response_data={"error": "maintenance"}, retry_after=retry_after
    )


def _server_error() -> PlatformAPIError:
    return PlatformAPIError("Server error", status_code=500, is_rate_limited=False)


def _authenticated_request(path: str = "/dashboard/") -> MagicMock:
    request = RequestFactory().get(path)
    SessionMiddleware(lambda r: None).process_request(request)
    request.session["customer_id"] = "1"
    request.session["email"] = "test@example.com"
    request.session["user_id"] = 1
    request.customer_id = "1"
    request.user = SimpleNamespace(id=1, is_authenticated=True)
    request._messages = FallbackStorage(request)
    return request


def tile_value(body: str, label: str) -> str:
    """What the stat tile beside this label actually rendered.

    `stat_tile.html` puts the label and the value in adjacent `<p>` elements, so the value is the
    first paragraph after the label's own. Asserted this way rather than by searching the page for
    "0", which every other tile can also contain - the question is what THIS tile claims.
    """
    after = body[body.index(label) :]
    match = re.search(r"</p>\s*<p[^>]*>(.*?)</p>", after, re.DOTALL)
    assert match, f"no value paragraph after the {label!r} tile label"
    return match.group(1).strip()


@override_settings(
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_SECRET="test-secret",
    PLATFORM_API_TIMEOUT=5,
    PORTAL_ID="portal-001",
    ROOT_URLCONF="config.urls",
)
class TheDashboardDuringAMaintenanceWindowTests(SimpleTestCase):
    SERVICES_TILE = "My Services"

    # --- layer one: the helper has to let a window through at all -----------------------------
    def test_the_services_helper_propagates_a_window(self) -> None:
        api = MagicMock()
        api.get_services_summary.side_effect = _maintenance_error()

        with self.assertRaises(PlatformAPIError):
            _get_services_data(api, "1", 1)

    def test_the_services_helper_still_swallows_an_ordinary_failure(self) -> None:
        """The other direction: a 500 keeps its graceful zero, which is the existing contract."""
        api = MagicMock()
        api.get_services_summary.side_effect = _server_error()

        self.assertEqual(_get_services_data(api, "1", 1), (0, {}))

    # --- layer two: the view has to classify it and the page has to say it --------------------
    @patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {}))
    @patch("apps.dashboard.views._get_customer_data", return_value=([], None))
    @patch("apps.dashboard.views._get_billing_data", return_value=([], {"total_invoices": 5}))
    @patch("apps.dashboard.views._get_services_data", side_effect=_maintenance_error())
    def test_a_window_is_announced_rather_than_counted_as_zero(
        self, _services: MagicMock, _billing: MagicMock, _customer: MagicMock, _tickets: MagicMock
    ) -> None:
        response = dashboard_view(_authenticated_request())
        body = response.content.decode()

        self.assertEqual(response.status_code, 200)
        self.assertIn("Scheduled maintenance", body, "the dashboard did not say the platform was in maintenance")
        self.assertNotEqual(
            tile_value(body, self.SERVICES_TILE),
            "0",
            "the services tile asserted the customer has none, which is a claim the platform never made",
        )

    @patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {}))
    @patch("apps.dashboard.views._get_customer_data", return_value=([], None))
    @patch("apps.dashboard.views._get_billing_data", return_value=([], {"total_invoices": 5}))
    @patch("apps.dashboard.views._get_services_data", return_value=(3, {}))
    def test_a_healthy_dashboard_says_nothing_about_maintenance(
        self, _services: MagicMock, _billing: MagicMock, _customer: MagicMock, _tickets: MagicMock
    ) -> None:
        """The positive control, so the new arm cannot fire on a working platform."""
        response = dashboard_view(_authenticated_request())
        body = response.content.decode()

        self.assertNotIn("Scheduled maintenance", body)
        self.assertEqual(tile_value(body, self.SERVICES_TILE), "3")

    @patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {}))
    @patch("apps.dashboard.views._get_customer_data", return_value=([], None))
    @patch("apps.dashboard.views._get_billing_data", return_value=([], {"total_invoices": 5}))
    @patch("apps.dashboard.views._get_services_data", side_effect=_server_error())
    def test_an_ordinary_failure_is_not_dressed_up_as_planned_work(
        self, _services: MagicMock, _billing: MagicMock, _customer: MagicMock, _tickets: MagicMock
    ) -> None:
        """A 500 must not borrow the maintenance wording. It is still flattened, as before."""
        response = dashboard_view(_authenticated_request())
        body = response.content.decode()

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Scheduled maintenance", body)

    @patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {"open_tickets": 0}))
    @patch("apps.dashboard.views._get_customer_data", return_value=([], None))
    @patch("apps.dashboard.views._get_billing_data", side_effect=_maintenance_error())
    @patch("apps.dashboard.views._get_services_data", return_value=(3, {"active_services": 3}))
    def test_a_window_does_not_poison_the_account_health_cache(
        self, _services: MagicMock, _billing: MagicMock, _customer: MagicMock, _tickets: MagicMock
    ) -> None:
        """The subtle one, and the regression this fix nearly introduced.

        The seeding guard reads `sections_rate_limited`, and it depends on that FLAG rather than on the
        data: `_empty_billing_summary()` returns a seven-key dict and is therefore TRUTHY, so the
        truthiness checks beside the flag cannot notice a billing section that failed. Caching that
        empty fallback suppresses the overdue/suspended/waiting banners for ACCOUNT_HEALTH_CACHE_TTL
        (300 seconds) even after the platform recovers - PR #164 review finding H2.

        Adding a second degraded state without teaching this reader about it re-creates H2 exactly.
        The setup isolates that: billing is in a window while services and tickets return truthy
        summaries, so the flag is the ONLY thing standing between the window and a poisoned cache.
        """
        request = _authenticated_request()

        dashboard_view(request)

        self.assertNotIn(
            "account_health_data",
            request.session,
            "a maintenance window seeded the 300-second health cache with empty fallback data",
        )

    @patch("apps.dashboard.views._get_ticket_data", return_value=([], 0, {"open_tickets": 0}))
    @patch("apps.dashboard.views._get_customer_data", return_value=([], None))
    @patch("apps.dashboard.views._get_billing_data", return_value=([], {"total_invoices": 5}))
    @patch("apps.dashboard.views._get_services_data", return_value=(3, {"active_services": 3}))
    def test_a_healthy_dashboard_still_seeds_the_cache(
        self, _services: MagicMock, _billing: MagicMock, _customer: MagicMock, _tickets: MagicMock
    ) -> None:
        """The control. Without it, a guard that never seeded would satisfy the test above."""
        request = _authenticated_request()

        dashboard_view(request)

        self.assertIn("account_health_data", request.session)
