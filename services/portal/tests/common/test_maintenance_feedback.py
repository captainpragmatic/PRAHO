"""A maintenance window must be distinguishable from a failure, and from a wrong password.

`PlatformAPIError` carried `is_rate_limited` and nothing else, so `handle_platform_error` - the
single funnel every portal list view routes platform failures through - produced a
template-visible signal for exactly one status, 429. A 503 fell through to `return {}`, and the
partials branch only on `rate_limited`, so a maintenance window rendered the friendly
"you have nothing yet" empty state. The views do set `"error": True`, and no template reads it.

This mirrors the rate-limit path deliberately, function for function, because that path already
proves the shape works end to end: a predicate, a message, a context builder, and one branch in
the funnel.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import Client, SimpleTestCase
from django.test.client import RequestFactory

from apps.api_client.services import PlatformAPIError
from apps.billing.services import _raise_if_degraded as billing_raise_if_degraded
from apps.common.rate_limit_feedback import (
    handle_platform_error,
    is_maintenance_error,
)
from apps.tickets.services import _raise_if_degraded as tickets_raise_if_degraded


def _request(path: str = "/billing/invoices/"):
    request = RequestFactory().get(path)
    SessionMiddleware(lambda r: None).process_request(request)
    request._messages = FallbackStorage(request)
    return request


class MaintenanceErrorClassificationTests(SimpleTestCase):
    def test_a_503_is_maintenance(self) -> None:
        self.assertTrue(PlatformAPIError("unavailable", status_code=503).is_maintenance)

    def test_a_429_is_not_maintenance(self) -> None:
        """The two signals must stay distinct; a throttle is not an outage."""
        error = PlatformAPIError("slow down", status_code=429)

        self.assertFalse(error.is_maintenance)
        self.assertTrue(error.is_rate_limited)

    def test_an_ordinary_failure_is_neither(self) -> None:
        error = PlatformAPIError("boom", status_code=500)

        self.assertFalse(error.is_maintenance)
        self.assertFalse(error.is_rate_limited)

    def test_the_predicate_ignores_unrelated_exceptions(self) -> None:
        self.assertFalse(is_maintenance_error(ValueError("not ours")))


class MaintenanceFeedbackFunnelTests(SimpleTestCase):
    def test_a_maintenance_error_produces_a_template_visible_flag(self) -> None:
        """Without this the partials fall through to their empty state."""
        context = handle_platform_error(
            _request(), PlatformAPIError("unavailable", status_code=503), logging.getLogger(__name__)
        )

        self.assertTrue(context.get("maintenance"))

    def test_the_flag_carries_a_message_and_somewhere_to_retry(self) -> None:
        context = handle_platform_error(
            _request(),
            PlatformAPIError("unavailable", status_code=503, retry_after=600),
            logging.getLogger(__name__),
        )

        self.assertTrue(context.get("maintenance_message"))
        self.assertEqual(context.get("maintenance_retry_url"), "/billing/invoices/")

    def test_a_maintenance_error_does_not_queue_the_generic_failure_message(self) -> None:
        """A specific notice beats a generic one; both at once is noise."""
        request = _request()

        handle_platform_error(
            request,
            PlatformAPIError("unavailable", status_code=503),
            logging.getLogger(__name__),
            fallback_message="Unable to load invoices.",
        )

        self.assertEqual([str(m) for m in get_messages(request)], [])

    # --- the two paths that must not change ----------------------------------------

    def test_rate_limiting_still_produces_its_own_context(self) -> None:
        context = handle_platform_error(
            _request(), PlatformAPIError("slow down", status_code=429, retry_after=8), logging.getLogger(__name__)
        )

        self.assertTrue(context.get("rate_limited"))
        self.assertFalse(context.get("maintenance"))

    def test_an_ordinary_failure_still_falls_back_to_a_message(self) -> None:
        request = _request()

        context = handle_platform_error(
            request,
            PlatformAPIError("boom", status_code=500),
            logging.getLogger(__name__),
            fallback_message="Unable to load invoices.",
        )

        self.assertEqual(context, {})
        self.assertEqual([str(m) for m in get_messages(request)], ["Unable to load invoices."])


class DegradedStateIsPropagatedNotFlattenedTests(SimpleTestCase):
    """Every place that asked "is this a throttle?" to decide whether to propagate.

    There were ten such places: two duplicated `_raise_if_rate_limited` helpers and eight inline
    `if e.is_rate_limited:` checks in the API client. Each one turned a maintenance 503 into
    `None` or an empty collection, and each therefore had to be found - fixing one would have
    left the rest reporting a maintenance window as missing data. `is_degraded` is the single
    property they now share, on the exception itself, because a helper in
    `rate_limit_feedback` cannot be imported by the API client without a cycle.
    """

    def test_a_throttle_is_degraded(self) -> None:
        self.assertTrue(PlatformAPIError("slow down", status_code=429).is_degraded)

    def test_maintenance_is_degraded(self) -> None:
        self.assertTrue(PlatformAPIError("unavailable", status_code=503).is_degraded)

    def test_an_ordinary_failure_is_not_degraded(self) -> None:
        """The distinction that matters: a real failure may still be flattened to empty."""
        self.assertFalse(PlatformAPIError("boom", status_code=500).is_degraded)

    def test_billing_re_raises_maintenance_instead_of_returning_an_empty_page(self) -> None:
        """This is the fully silent symptom: no toast, no error, just "no invoices"."""
        with self.assertRaises(PlatformAPIError):
            billing_raise_if_degraded(PlatformAPIError("unavailable", status_code=503))

    def test_billing_still_flattens_an_ordinary_failure(self) -> None:
        billing_raise_if_degraded(PlatformAPIError("boom", status_code=500))

    def test_tickets_re_raises_maintenance_too(self) -> None:
        """The duplicated helper had to be found as well, not just the first one."""
        with self.assertRaises(PlatformAPIError):
            tickets_raise_if_degraded(PlatformAPIError("unavailable", status_code=503))


class LoginDuringMaintenanceTests(SimpleTestCase):
    """The symptom the owner reported: a maintenance window read as a wrong password.

    `authenticate_customer` converted every non-429 error to `None`, and `None` means "invalid
    credentials" to the view - so the customer retyped a correct password and was told again that
    it was wrong. The branch that would have been right, at `users/views.py:317-323`, was
    unreachable for a 503 for exactly that reason.
    """

    def test_a_maintenance_window_is_not_reported_as_a_wrong_password(self) -> None:
        with patch(
            "apps.users.views.api_client.authenticate_customer",
            side_effect=PlatformAPIError("unavailable", status_code=503, retry_after=600),
        ):
            response = Client().post("/login/", {"email": "someone@example.com", "password": "correct-horse"})

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Invalid email address or password")
        self.assertContains(response, "scheduled maintenance")

    def test_the_form_is_disabled_so_retyping_is_not_invited(self) -> None:
        """Asserts the button's own attribute, which took three attempts to get right.

        `assertContains(response, "disabled")` proves nothing: the shared button component always
        emits `disabled:opacity-50 disabled:cursor-not-allowed` in its class list, so the literal
        string is on every page that has a button. Comparing total counts between the two renders
        proves nothing either - the maintenance render additionally carries the alert and a
        populated error summary, which shift the count on their own. Measured: 22 against 20 with
        the fix, and still higher without it.

        ` disabled>` is the bare attribute closing the button tag: 1 against 0.
        """
        credentials = {"email": "someone@example.com", "password": "correct-horse"}

        with patch(
            "apps.users.views.api_client.authenticate_customer",
            side_effect=PlatformAPIError("unavailable", status_code=503),
        ):
            blocked = Client().post("/login/", credentials)
        with patch("apps.users.views.api_client.authenticate_customer", return_value=None):
            reachable = Client().post("/login/", credentials)

        self.assertIn(b" disabled>", blocked.content)
        self.assertNotIn(b" disabled>", reachable.content)

    def test_a_genuinely_wrong_password_still_says_so(self) -> None:
        """The distinction has to work in both directions."""
        with patch("apps.users.views.api_client.authenticate_customer", return_value=None):
            response = Client().post("/login/", {"email": "someone@example.com", "password": "wrong"})

        self.assertContains(response, "Invalid email address or password")
