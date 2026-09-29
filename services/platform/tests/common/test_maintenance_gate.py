"""Maintenance mode is enforced on the customer surface, not only the staff one.

ADR-0042 records that maintenance mode "is enforced, not decorative". That was verified only
against the staff browser surface. Every existing test drives the middleware directly with a
`RequestFactory` on paths like `/dashboard/` and `/auth/login/`, and `config/settings/test.py`
rebuilds `MIDDLEWARE` without the gate at all - so no Django test-client request could reach it,
and no test used an `/api/` path.

`/api/` is not in `EXEMPT_PREFIXES`, and it is every request the customer portal makes. Enabling
maintenance therefore takes the portal down, which is correct, but the portal cannot tell that is
what happened: the gate answers with HTML while the portal's client parses JSON, so the real
message is discarded at `api_client/services.py:341-343` and becomes "Invalid response format".
Everything downstream then treats a maintenance window as a generic failure - empty invoice
lists, and a login indistinguishable from a wrong password.

The gate is added here through `override_settings` rather than restored globally in the test
settings. Restoring it globally was tried and costs more than it is worth today: it broke five
tests, three of them because they `@patch("apps.settings.services.SettingsService")` as a whole
class so every unrelated settings read returns a truthy `MagicMock` and maintenance switches
itself on, and one because it asserts `assertNumQueries(0)` on a hardened endpoint - the endpoint
still makes none, but the gate makes one, since test settings use `DummyCache` and nothing is
cached. Weakening that assertion to accommodate middleware would be the wrong trade.
"""

from __future__ import annotations

import json

from django.conf import settings as django_settings
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.settings.services import SettingsService
from tests.factories.core_factories import create_admin_user

GATE = "apps.common.middleware.MaintenanceModeMiddleware"


def middleware_with_gate() -> list[str]:
    """The configured stack plus the gate, positioned as `base.py` positions it.

    Derived rather than hardcoded so it cannot drift from the real stack, and a no-op if the gate
    is ever restored to the test settings globally.
    """
    stack = list(django_settings.MIDDLEWARE)
    if GATE in stack:
        return stack
    anchor = "django.contrib.messages.middleware.MessageMiddleware"
    stack.insert(stack.index(anchor) + 1, GATE)
    return stack


@override_settings(MIDDLEWARE=middleware_with_gate())
class MaintenanceGateOnTheApiSurfaceTests(TestCase):
    API_PATH = "/api/localisation/"

    def _enable(self) -> None:
        SettingsService.update_setting("system.maintenance_mode", True)

    # --- what maintenance must do -------------------------------------------------

    def test_the_api_surface_is_gated_by_the_runtime_setting(self) -> None:
        """Through the real stack, driven by the setting rather than the deployment override."""
        self._enable()

        response = self.client.post(self.API_PATH)

        self.assertEqual(response.status_code, 503)

    def test_an_api_client_receives_json_it_can_parse(self) -> None:
        """The portal's client calls `response.json()`; HTML there loses the reason entirely."""
        self._enable()

        response = self.client.post(self.API_PATH)

        self.assertEqual(response["Content-Type"].split(";")[0], "application/json")
        body = json.loads(response.content)
        self.assertIn("maintenance", json.dumps(body).lower())

    def test_the_response_still_tells_a_client_when_to_come_back(self) -> None:
        self._enable()

        response = self.client.post(self.API_PATH)

        self.assertEqual(response["Retry-After"], "600")

    # --- what must not change ------------------------------------------------------

    def test_a_browser_path_still_receives_html(self) -> None:
        """A human needs a page, not a JSON document."""
        self._enable()

        response = self.client.get("/app/")

        self.assertEqual(response.status_code, 503)
        self.assertIn("text/html", response["Content-Type"])

    def test_staff_still_pass_through(self) -> None:
        self._enable()
        self.client.force_login(create_admin_user(username="gate_admin"))

        response = self.client.get(reverse("settings:home"))

        self.assertEqual(response.status_code, 200)

    def test_the_health_endpoint_stays_reachable(self) -> None:
        """Whatever is watching the platform must still be able to see it."""
        self._enable()

        response = self.client.get("/settings/api/health/")

        self.assertNotEqual(response.status_code, 503)

    def test_nothing_is_gated_when_maintenance_is_off(self) -> None:
        response = self.client.post(self.API_PATH)

        self.assertNotEqual(response.status_code, 503)
