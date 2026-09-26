"""Regression tests for the two 500s the widening introduced."""
from __future__ import annotations

from unittest.mock import patch

from django.test import Client, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.billing.services import RecurringPaymentsService


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
