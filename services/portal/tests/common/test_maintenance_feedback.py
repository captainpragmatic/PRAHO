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
import time
from datetime import timedelta
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import Client, SimpleTestCase, override_settings
from django.test.client import RequestFactory
from django.utils import timezone

from apps.api_client.services import PlatformAPIError
from apps.billing.services import _raise_if_degraded as billing_raise_if_degraded
from apps.common.rate_limit_feedback import (
    handle_platform_error,
    is_maintenance_error,
)
from apps.services.services import ServicesAPIClient
from apps.services.services import _raise_if_degraded as services_raise_if_degraded
from apps.tickets.services import _raise_if_degraded as tickets_raise_if_degraded


def _request(path: str = "/billing/invoices/"):
    request = RequestFactory().get(path)
    SessionMiddleware(lambda r: None).process_request(request)
    request._messages = FallbackStorage(request)
    return request


class MaintenanceErrorClassificationTests(SimpleTestCase):
    def test_a_503_the_platform_marked_is_maintenance(self) -> None:
        error = PlatformAPIError("unavailable", status_code=503, response_data={"error": "maintenance"})
        self.assertTrue(error.is_maintenance)
        self.assertTrue(error.is_degraded)

    def test_a_bare_503_is_degraded_but_not_maintenance(self) -> None:
        """Narrowed deliberately. This test asserted the opposite and was wrong.

        `apps/api/billing/views.py` answers 503 for arbitrary document-list errors, so keying on the
        status alone told a customer "scheduled maintenance - your data is safe" in the middle of a
        real failure. Only the gate's own `{"error": "maintenance"}` marker may make that claim; an
        unmarked 503 is still surfaced, just not described as planned.
        """
        error = PlatformAPIError("unavailable", status_code=503, response_data={"error": "boom"})
        self.assertFalse(error.is_maintenance)
        self.assertTrue(error.is_degraded)

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

    def test_services_re_raises_maintenance_too(self) -> None:
        """The THIRD copy, which the original sweep missed entirely. See the class below."""
        with self.assertRaises(PlatformAPIError):
            services_raise_if_degraded(PlatformAPIError("unavailable", status_code=503))

    def test_services_still_flattens_an_ordinary_failure(self) -> None:
        services_raise_if_degraded(PlatformAPIError("boom", status_code=500))


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
            side_effect=PlatformAPIError(
                "unavailable", status_code=503, response_data={"error": "maintenance"}, retry_after=600
            ),
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


class LoginDuringAnUndeclaredOutageTests(SimpleTestCase):
    """A 502, a 504, or a 503 the platform did not mark still cannot let anyone log in.

    The view keyed on `is_maintenance`, so narrowing that flag would have sent every undeclared
    outage back to the generic branch - which is the reported bug all over again, a real outage
    reported as a wrong password. It keys on `is_unavailable` now, and the wording is the only thing
    that differs between the two cases.
    """

    def _post_login_with(self, error: PlatformAPIError) -> HttpResponse:
        with patch("apps.users.views.api_client.authenticate_customer", side_effect=error):
            return Client().post("/login/", {"email": "someone@example.com", "password": "correct-horse"})

    def test_an_unmarked_503_disables_the_form_without_claiming_maintenance(self) -> None:
        response = self._post_login_with(
            PlatformAPIError("boom", status_code=503, response_data={"error": "boom"}, retry_after=600)
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b" disabled>", response.content, "the submit button must still be disabled")
        body = response.content.decode().lower()
        self.assertIn("temporarily unavailable", body)
        self.assertNotIn("your data is safe", body, "nobody knows that during an unexplained failure")

    def test_a_gateway_error_is_treated_the_same_way(self) -> None:
        for status in (502, 504):
            with self.subTest(status=status):
                response = self._post_login_with(PlatformAPIError("gateway", status_code=status))
                self.assertEqual(response.status_code, 200)
                self.assertIn(b" disabled>", response.content)

    def test_a_declared_window_still_says_so(self) -> None:
        """The positive control: the distinction is in the wording, not in whether it is surfaced."""
        response = self._post_login_with(
            PlatformAPIError("maint", status_code=503, response_data={"error": "maintenance"}, retry_after=600)
        )

        body = response.content.decode().lower()
        self.assertIn("scheduled maintenance", body)
        self.assertIn("your data is safe", body)


class TheMaintenanceAlertItselfTests(SimpleTestCase):
    """The alert's own heading and body, which no other part of the page can supply.

    Every login assertion above is satisfied by the FORM ERROR. `get_degraded_message` puts
    "We're carrying out scheduled maintenance. Your data is safe - please try again in 600 seconds."
    into `form.add_error`, so a lowercased body contains "scheduled maintenance" and "your data is
    safe" whether or not the alert rendered at all - and the whole portal unit suite passed with the
    context fix reverted. Measured, not assumed: 1183 passed against a bare `maintenance = True`.

    What was actually broken behind that green: the view set the boolean and nothing else, so the
    heading fell through to its `|default:` ("Temporarily unavailable" on a window the platform had
    declared) and `maintenance_message` was never set at ALL, rendering an empty paragraph. Both
    were found by running the browser test, which asserts "Scheduled maintenance" with a capital S -
    the one spelling only the `<h3>` produces. Case-folding the body is what hid it.

    So these assertions deliberately read the context keys the template consumes, and the heading as
    an element's whole text content, rather than prose the page carries for other reasons.
    """

    DECLARED = PlatformAPIError(
        "maint", status_code=503, response_data={"error": "maintenance"}, retry_after=600
    )
    UNDECLARED = PlatformAPIError("boom", status_code=503, response_data={"error": "boom"}, retry_after=600)
    # A paragraph carrying at least one character that is neither whitespace nor the start of a tag.
    # `<p[^>]*>\s*\S` would be satisfied by `<p class="x"></p>`, because `\S` matches the `<` of the
    # closing tag - which is the empty paragraph this is meant to rule out.
    PARAGRAPH_WITH_TEXT = r"<p[^>]*>\s*[^<\s]"

    def _post_login_with(self, error: PlatformAPIError) -> HttpResponse:
        with patch("apps.users.views.api_client.authenticate_customer", side_effect=error):
            return Client().post("/login/", {"email": "someone@example.com", "password": "correct-horse"})

    def _alert_region(self, response: HttpResponse, heading: str) -> str:
        """The alert's OWN markup, sliced between its heading and its retry link.

        Both halves of this page put their message in a `<p>`: the alert uses `text-blue-100/90` and
        `components/form_error_summary.html` uses `text-red-100`. So "some `<p>` contains this
        sentence" is satisfied by the FORM ERROR, which carries the same words - the original trap,
        one level down. Slicing to the alert's own region is what makes the assertion about the alert.

        Anchored on the alert's own content rather than on its CSS classes, so restyling it cannot
        fail this spuriously. `users/login.html` renders the alert before the form, so the region
        cannot reach the error summary.
        """
        body = response.content.decode()
        start = body.index(heading)
        return body[start : body.index("Try again", start)]

    def test_a_declared_window_supplies_the_heading_the_template_reads(self) -> None:
        response = self._post_login_with(self.DECLARED)

        # Rendered first, deliberately. A missing context key raises KeyError, so asserting the
        # context before the markup means a regression short-circuits the test before it ever
        # reaches the customer-visible half - and that half would then be unproven.
        self.assertContains(response, ">Scheduled maintenance<")
        self.assertEqual(response.context["maintenance_heading"], "Scheduled maintenance")

    def test_the_alert_body_is_not_empty(self) -> None:
        """The pre-existing half of the bug: a blue box with a heading and no explanation.

        Asserted positively. The first version only checked that the exact empty-paragraph markup was
        absent, which deleting the paragraph altogether also satisfies - absence of an empty `<p>` is
        not evidence of a full one.
        """
        response = self._post_login_with(self.DECLARED)
        alert = self._alert_region(response, "Scheduled maintenance")

        self.assertRegex(alert, self.PARAGRAPH_WITH_TEXT, "the alert rendered no paragraph with text in it")
        self.assertIn("Your data is safe", alert)
        self.assertIn("Your data is safe", response.context["maintenance_message"])

    def test_an_undeclared_outage_does_not_announce_itself_as_planned_work(self) -> None:
        response = self._post_login_with(self.UNDECLARED)
        alert = self._alert_region(response, "Temporarily unavailable")

        self.assertNotContains(response, ">Scheduled maintenance<")
        self.assertRegex(alert, self.PARAGRAPH_WITH_TEXT, "the alert rendered no paragraph with text in it")
        self.assertNotIn("Your data is safe", alert, "nobody knows that during an unexplained failure")
        self.assertEqual(response.context["maintenance_heading"], "Temporarily unavailable")
        self.assertNotIn("Your data is safe", response.context["maintenance_message"])

    def test_a_wrong_password_renders_no_alert_at_all(self) -> None:
        """`maintenance` used to be set to False explicitly; it is now simply absent on this path."""
        with patch("apps.users.views.api_client.authenticate_customer", return_value=None):
            response = Client().post("/login/", {"email": "someone@example.com", "password": "wrong"})

        self.assertFalse(response.context.get("maintenance"))
        self.assertNotContains(response, ">Scheduled maintenance<")
        self.assertNotContains(response, ">Temporarily unavailable<")


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class TheServicesAppWasSkippedByTheWideningTests(SimpleTestCase):
    """Billing got `_raise_if_degraded` at eight sites, tickets at one, services at none.

    So during a window the dashboard badge read "0 active services", the plans list was empty and the
    usage panel showed zeros - the reported bug itself, in the one app the sweep missed. What hid it:
    `get_customer_services`, `get_service_detail` and `request_service_action` always re-raised, so
    the services LIST page did reach its `{% elif maintenance %}` arm and looked correct. The four
    calls below did not.

    The callers were checked one at a time rather than widened mechanically. Four of them handled only
    rate-limiting and then fell through to `messages.error("Service not found or access denied.")`, so
    a blind widening would have replaced an empty page with a false statement about the customer's own
    account. Two of those already made that statement before the widening, because the detail call
    always re-raised.
    """

    MAINTENANCE = PlatformAPIError(
        "unavailable", status_code=503, response_data={"error": "maintenance"}, retry_after=600
    )
    ORDINARY = PlatformAPIError("boom", status_code=500)

    def _platform_raising(self, error: PlatformAPIError):
        return patch("apps.services.services.ServicesAPIClient._make_request", side_effect=error)

    # `session_auth_hash`, `validated_at` and `next_validate_at` are required since the session
    # validation middleware landed on master: without all three it calls `validate_session_secure`,
    # which these tests do not mock, and the request is redirected to /login/ instead. The symptom is
    # a 302 with an EMPTY body - which silently satisfies any assertNotIn, so a test can pass
    # vacuously rather than fail. Same shape as `tests/tickets/test_ticket_detail_view.py`.
    def _session_client(self) -> Client:
        client = Client()
        session = client.session
        now = timezone.now()
        session.update(
            {
                "customer_id": 1,
                "user_id": 2,
                "selected_customer_id": 1,
                "user_memberships": [{"customer_id": 1, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
                "session_auth_hash": "test-session",
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
            }
        )
        session.save()
        return client

    def _calls(self, client: ServicesAPIClient) -> dict[str, object]:
        return {
            "get_services_summary": lambda: client.get_services_summary(1, 2),
            "get_service_usage": lambda: client.get_service_usage(1, 2, 3),
            "get_service_domains": lambda: client.get_service_domains(1, 3),
            "get_available_plans": lambda: client.get_available_plans(1),
        }

    def test_all_four_flattening_calls_now_propagate_a_window(self) -> None:
        client = ServicesAPIClient()
        for name, call in self._calls(client).items():
            with self.subTest(call=name), self._platform_raising(self.MAINTENANCE), self.assertRaises(PlatformAPIError):
                call()

    def test_an_ordinary_failure_is_still_flattened(self) -> None:
        """Both directions. A 500 must keep returning the graceful shape, not start breaking pages."""
        client = ServicesAPIClient()
        with self._platform_raising(self.ORDINARY):
            self.assertEqual(client.get_available_plans(1), [])
            self.assertEqual(client.get_service_domains(1, 3), [])
            self.assertEqual(client.get_services_summary(1, 2).get("active_services"), 0)
            self.assertEqual(client.get_service_usage(1, 2, 3).get("bandwidth_used"), 0)

    def test_a_window_is_not_reported_as_the_service_not_existing(self) -> None:
        """The misstatement, which predates the widening and is the worse half of this.

        `get_service_detail` always re-raised, so opening a service during a window already answered
        "Service not found or access denied" - a claim about the customer's own account that is false.
        """
        with self._platform_raising(self.MAINTENANCE):
            response = self._session_client().get("/services/3/", follow=True)

        body = response.content.decode()
        self.assertNotIn("Service not found or access denied", body)
        self.assertIn("scheduled maintenance", body.lower())

    def test_the_usage_panel_says_maintenance_rather_than_failing_silently(self) -> None:
        """Capital S: the alert's own heading, which nothing else on this partial produces."""
        with self._platform_raising(self.MAINTENANCE):
            response = self._session_client().get("/services/3/usage/")

        body = response.content.decode()
        self.assertIn("Scheduled maintenance", body)
        self.assertNotIn("Unable to load usage data", body)

    def test_an_ordinary_usage_failure_does_not_borrow_the_maintenance_wording(self) -> None:
        """The other direction, so the new arm cannot fire for a failure nobody declared."""
        with self._platform_raising(self.ORDINARY):
            response = self._session_client().get("/services/3/usage/")

        body = response.content.decode()
        self.assertNotIn("Scheduled maintenance", body)
        self.assertNotIn("Temporarily unavailable", body)

    def test_an_ordinary_failure_marks_the_usage_result_so_the_panel_can_say_so(self) -> None:
        """`usage_chart.html` has always had an `{% if usage.error %}` arm, and it was unreachable.

        `get_service_usage` returned its zero shape WITHOUT the one key that template branches on, so
        a platform 500 rendered a chart of zeros indistinguishable from a service that genuinely used
        nothing - the same "a failure shown as data" bug this branch exists to fix, one floor down.
        Found while writing a test that asserted the arm fired: it did not, and that was the evidence.
        """
        with self._platform_raising(self.ORDINARY):
            usage = ServicesAPIClient().get_service_usage(1, 2, 3)

        self.assertTrue(usage.get("error"), "the fallback omitted the key its own template reads")
        self.assertEqual(usage.get("bandwidth_used"), 0, "the zero shape must survive, for consumers that read it")

    def test_the_usage_panel_says_it_could_not_load_on_an_ordinary_failure(self) -> None:
        """The customer-visible half of the same defect."""
        with self._platform_raising(self.ORDINARY):
            response = self._session_client().get("/services/3/usage/")

        self.assertIn("Unable to load usage data", response.content.decode())
