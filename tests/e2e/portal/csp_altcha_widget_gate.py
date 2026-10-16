"""The public forms' proof-of-work solves in the browser under the strict CSP.

The ALTCHA widget, its Romanian strings and the script registering its worker load as modules, and
the PBKDF2 worker is served from the portal's origin: the strict policy admits no blob: worker and
no inline script. This drives a real verification and requires a solution with ZERO violations.

Run via `make test-e2e-csp CSP_PROFILE=<profile>`. The filename is intentionally excluded from
default pytest discovery, like the other CSP gates.
"""

import os

from playwright.sync_api import Page

from tests.e2e.helpers import BASE_URL
from tests.e2e.helpers.csp import (
    install_csp_violation_capture,
    read_csp_violations,
)

STRICT_CSP_PROFILES = frozenset({"phase2-target", "phase3-target"})


def test_altcha_widget_solves_under_strict_csp(page: Page) -> None:
    assert os.environ.get("EXPECTED_CSP_PROFILE") in STRICT_CSP_PROFILES, (
        "EXPECTED_CSP_PROFILE must be phase2-target or phase3-target. "
        "Run via `make test-e2e-csp CSP_PROFILE=<profile>`."
    )
    install_csp_violation_capture(page)

    page.goto(f"{BASE_URL}/password-reset/", wait_until="domcontentloaded")
    page.wait_for_function("() => customElements.get('altcha-widget') && globalThis.$altcha")
    page.evaluate("() => document.querySelector('altcha-widget').verify()")
    page.wait_for_function(
        "() => document.querySelector('altcha-widget').getState() === 'verified'", timeout=30000
    )

    assert page.locator('input[name="altcha"]').input_value(), "the solved widget left no payload"
    assert read_csp_violations(page) == []
