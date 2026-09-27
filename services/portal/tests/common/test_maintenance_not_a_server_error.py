"""Regression tests for the two 500s the widening introduced."""
from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.billing.services import RecurringPaymentsService
from apps.common.rate_limit_feedback import get_degraded_message


def maintenance_error() -> PlatformAPIError:
    return PlatformAPIError("Service Unavailable", status_code=503, retry_after=600)


@override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cache")
class MaintenanceMustNotBecomeAServerErrorTests(SimpleTestCase):
    """Widening `_raise_if_degraded` across 11 sites turned graceful degradation into 500s.

    Both cases below were 302/JSON on master, became 500 with the widening, and are back. Each is the
    positive control for one of the two reverted decisions.
    """

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        for key, value in {"user_id": 456, "customer_id": 123, "active_customer_id": 123}.items():
            session[key] = value
        session.save()

    @patch("apps.users.views.api_client.get_customer_profile", side_effect=maintenance_error())
    def test_the_backup_codes_page_redirects_during_maintenance_rather_than_500(self, _profile) -> None:
        response = self.client.get("/mfa/backup-codes/")
        self.assertNotEqual(response.status_code, 500, "a maintenance window must not 500 this page")
        self.assertEqual(response.status_code, 302)

    @patch("apps.billing.services.RecurringPaymentsService._post")
    def test_the_recurring_payments_page_does_not_500_during_maintenance(self, post) -> None:
        """Patched at `_post`, which is where the maintenance error is caught and turned into a dict.

        Patching the view's service class would test the mock; patching `_post` exercises the real
        `except` clause that decides whether maintenance propagates.
        """
        post.side_effect = lambda *a, **kw: {"success": False, "error": "unavailable"}
        response = self.client.get("/billing/automatic-payments/")
        self.assertNotEqual(response.status_code, 500)

    @patch("apps.billing.services.PlatformAPIClient")
    def test_a_maintenance_error_inside_the_service_yields_a_dict_not_an_exception(self, client_class) -> None:
        """The actual regression: `_raise_if_degraded` here made five uncaught callers raise.

        Patched at the CONSTRUCTOR, not the attribute. `RecurringPaymentsService.__init__` assigns
        `self.api_client`, so patching the class attribute creates a phantom the instance never
        consults - the first version of this test passed identically with the fix reverted, which is
        the only reason it was caught.
        """
        client_class.return_value.post.side_effect = maintenance_error()
        result = RecurringPaymentsService().overview(customer_id=123, user_id=456)

        self.assertFalse(result["success"])
        self.assertIn("unavailable", result["error"])


class OnlyADeclaredMaintenanceMayClaimToBePlannedTests(SimpleTestCase):
    """A bare 503 is not maintenance, and saying it is tells the customer a comforting untruth.

    `is_maintenance` defaulted from `status_code == 503` alone. But
    `services/platform/apps/api/billing/views.py:587` catches arbitrary document-list exceptions and
    answers 503, so a real failure announced itself as "scheduled maintenance" and promised "your data
    is safe" — during an outage where nobody knows that. The platform's own gate marks its body
    `{"error": "maintenance"}`; only that may claim to be planned work.
    """

    def error(self, status: int, body: dict[str, object] | None = None) -> PlatformAPIError:
        return PlatformAPIError("failed", status_code=status, response_data=body, retry_after=600)

    def test_a_marked_503_is_maintenance(self) -> None:
        exc = self.error(503, {"error": "maintenance", "retry_after": 600})
        self.assertTrue(exc.is_maintenance)
        self.assertTrue(exc.is_unavailable)
        self.assertTrue(exc.is_degraded)

    def test_an_unmarked_503_is_unavailable_but_not_maintenance(self) -> None:
        """The document-list case: a real error the platform happened to answer with 503."""
        exc = self.error(503, {"error": "Failed to list documents"})
        self.assertFalse(exc.is_maintenance)
        self.assertTrue(exc.is_unavailable)
        self.assertTrue(exc.is_degraded, "it must still be surfaced rather than shown as an empty list")

    def test_502_and_504_are_degraded_too(self) -> None:
        """The first version of this change covered only 503, so a gateway error stayed invisible."""
        for status in (502, 504):
            with self.subTest(status=status):
                exc = self.error(status)
                self.assertFalse(exc.is_maintenance)
                self.assertTrue(exc.is_degraded)

    def test_a_genuine_failure_is_not_degraded(self) -> None:
        exc = self.error(500, {"error": "boom"})
        self.assertFalse(exc.is_degraded)

    def test_the_wording_differs_between_the_two(self) -> None:
        planned = get_degraded_message(self.error(503, {"error": "maintenance"}))
        outage = get_degraded_message(self.error(503, {"error": "Failed to list documents"}))
        self.assertIn("scheduled maintenance", planned.lower())
        self.assertIn("your data is safe", planned.lower())
        self.assertNotIn("your data is safe", outage.lower())
        self.assertIn("temporarily unavailable", outage.lower())


@override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cache")
class DegradedJsonEndpointsAnswer503NotServerErrorTests(SimpleTestCase):
    """The two endpoints the widening turned into 500s."""

    def setUp(self) -> None:
        cache.clear()
        self.client = Client()
        session = self.client.session
        for key, value in {"active_customer_id": 123, "customer_id": 123, "user_id": 456}.items():
            session[key] = value
        session.save()

    @patch("apps.billing.views.InvoiceViewService")
    def test_the_dashboard_widget_answers_503(self, service_class) -> None:
        service_class.return_value.get_invoice_summary.side_effect = PlatformAPIError(
            "unavailable", status_code=503, response_data={"error": "maintenance"}, retry_after=600
        )
        response = self.client.get("/billing/dashboard-widget/")
        self.assertNotEqual(response.status_code, 500, "maintenance is not a server fault")
        self.assertEqual(response.status_code, 503)
