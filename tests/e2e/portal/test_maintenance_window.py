"""A real maintenance window, driven through the platform, observed in the portal.

Every other check of maintenance mode is a unit test: the middleware with a `RequestFactory`, or
the portal's error funnel with a constructed exception. None of them crosses the HTTP boundary,
and that gap is exactly where the reported bug lived - the platform was gating correctly and the
portal was rendering "you have no documents".

This drives the whole chain: a staff user flips the runtime setting on the platform over its own
HTTP surface, and the assertions are made in a browser against the portal.

Why the toggle goes over HTTP rather than through the ORM: the e2e settings use `LocMemCache`,
which is per-process. A write from this test process would never invalidate the SERVER's copy, so
the server would keep serving the old value for up to an hour. Going through the platform's own
save endpoint is what makes it take effect - the same reason `scripts/qa_settings_sweep.py` does
it that way, and its mechanics are reused here.

Staff are exempt from the gate, which is what makes turning it back OFF possible at all.

One ordering detail is load-bearing. The "before" step visits the invoice list while maintenance
is off, which warms the five-minute membership cache in `common/decorators.py`. Without that, a
cold cache during maintenance returns a plain-text `403 Role not found` instead of the portal
page - a known gap that is deliberately unfixed, because it sits on an authorization fail-closed
path whose contract deserves its own change. The test would be flaky without the warm-up, and the
warm-up is honest: a customer who was just using the portal is precisely who hits a maintenance
window.

`customer_page` is used rather than `monitored_customer_page`: this test deliberately induces
503s, so the monitor's network-error check would fight its own purpose.
"""

from __future__ import annotations

import json
import re

import pytest
import requests

from tests.e2e.helpers import (
    BASE_URL,
    LOGIN_URL,
    PLATFORM_BASE_URL,
    PLATFORM_LOGIN_URL,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
)

KEY = "system.maintenance_mode"
TIMEOUT = 20
EMPTY_STATE = "No documents found"
MAINTENANCE_HEADING = "Scheduled maintenance"
DOCUMENT_ROW = '[data-action="navigate"]'


class MaintenanceSwitch:
    """Flips the runtime setting through the platform's own save endpoint, as staff."""

    def __init__(self) -> None:
        self._session = requests.Session()
        self._sign_in()

    def _csrf_from(self, path: str) -> str:
        html = self._session.get(f"{PLATFORM_BASE_URL}{path}", timeout=TIMEOUT).text
        match = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', html)
        assert match, f"no CSRF token on {path}"
        return match.group(1)

    def _sign_in(self) -> None:
        self._session.post(
            f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}",
            data={
                "email": SUPERUSER_EMAIL,
                "password": SUPERUSER_PASSWORD,
                "csrfmiddlewaretoken": self._csrf_from(PLATFORM_LOGIN_URL),
            },
            headers={"Referer": f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}"},
            timeout=TIMEOUT,
        )
        landing = self._session.get(f"{PLATFORM_BASE_URL}/settings/", timeout=TIMEOUT)
        assert landing.status_code == 200, "staff sign-in failed; this test cannot drive maintenance mode"

    def _baseline(self) -> str | None:
        response = self._session.get(f"{PLATFORM_BASE_URL}/settings/api/{KEY}/", timeout=TIMEOUT)
        return response.json()["setting"].get("updated_at") if response.status_code == 200 else None

    def set(self, active: bool) -> None:
        response = self._session.post(
            f"{PLATFORM_BASE_URL}/settings/save/",
            data=json.dumps(
                {"changes": {KEY: active}, "baselines": {KEY: self._baseline()}, "reason": "E2E maintenance window"}
            ),
            headers={
                "X-CSRFToken": self._session.cookies.get("csrftoken"),
                "Content-Type": "application/json",
                "Referer": PLATFORM_BASE_URL,
            },
            timeout=TIMEOUT,
        )
        assert response.status_code == 200, f"could not set {KEY}={active}: {response.status_code} {response.text[:200]}"


@pytest.fixture
def maintenance_switch():
    """Guarantees the platform is left usable, and proves it rather than assuming it.

    Maintenance is global state on a stack shared by 311 tests, and the acceptance bar is two
    clean consecutive runs - so leaving it on would not fail one test, it would fail everything
    after it. Teardown therefore clears it and then checks the portal actually serves again. A
    failure to restore raises here on purpose: a loud failure beats a poisoned stack.
    """
    switch = MaintenanceSwitch()
    switch.set(False)
    try:
        yield switch
    finally:
        switch.set(False)
        recovered = requests.get(f"{BASE_URL}{LOGIN_URL}", timeout=TIMEOUT)
        assert recovered.status_code == 200, "portal did not recover after maintenance was cleared"


def test_a_maintenance_window_is_announced_and_recovered_from(customer_page, browser, maintenance_switch):
    """OFF to ON to OFF, asserting what a customer sees at each step."""
    invoices = f"{BASE_URL}/billing/invoices/"

    # --- OFF: real documents, and the membership cache warmed for what follows -----
    customer_page.goto(invoices)
    documents_before = customer_page.locator(DOCUMENT_ROW).count()
    assert documents_before > 0, "fixture customer should hold documents before the window opens"
    assert EMPTY_STATE not in customer_page.content()

    # --- ON ------------------------------------------------------------------------
    maintenance_switch.set(True)

    customer_page.goto(invoices)
    body = customer_page.content()
    assert MAINTENANCE_HEADING in body, "a logged-in customer was not told the platform is in maintenance"
    assert EMPTY_STATE not in body, "maintenance still rendered as 'you have no documents'"

    anonymous_context = browser.new_context()
    try:
        anonymous = anonymous_context.new_page()
        anonymous.goto(f"{BASE_URL}{LOGIN_URL}")
        anonymous.fill("#id_email", "someone@example.com")
        anonymous.fill("#id_password", "correct-horse-battery-staple")
        anonymous.click("button[type=submit]")
        login_body = anonymous.content()
        assert MAINTENANCE_HEADING in login_body, "the login page did not mention maintenance"
        assert "Invalid email address or password" not in login_body, (
            "a maintenance window was reported to the visitor as a wrong password"
        )
    finally:
        anonymous_context.close()

    # --- OFF: the same documents, with their identity intact -----------------------
    maintenance_switch.set(False)

    customer_page.goto(invoices)
    recovered = customer_page.content()
    assert MAINTENANCE_HEADING not in recovered, "the maintenance notice outlived the window"
    assert customer_page.locator(DOCUMENT_ROW).count() == documents_before, (
        "documents did not come back exactly as they were"
    )
