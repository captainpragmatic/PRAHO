"""Alpine interaction lock-in gate under the strict phase2-target CSP (UNIT 0.3 Part B).

Proves that removing script-src 'unsafe-inline' does NOT break Alpine-driven
interactions. The cookie-consent banner is the ideal witness: cookieConsent() is
defined in an INLINE <script> and consumed by x-data="cookieConsent()", so under
the strict policy the whole chain only works if the inline script's nonce is
honoured — then the component's assignment, nested state, and method-call
expressions all run with ZERO CSP violations. This is the lock-in baseline that
PR 2's @alpinejs/csp build swap must keep green.

Run via `make test-e2e-csp CSP_PROFILE=phase2-target` (boots the portal under the
enforced strict profile). The filename is intentionally excluded from default
pytest discovery — the ordinary portal E2E suite runs the current profile.
"""

import os

import pytest
from playwright.sync_api import Page

from tests.e2e.helpers import BASE_URL
from tests.e2e.helpers.auth import wait_for_alpine
from tests.e2e.helpers.csp import (
    install_csp_violation_capture,
    read_csp_violations,
)

STRICT_CSP_PROFILES = frozenset({"phase2-target", "phase3-target"})

# The banner must stay visible so we can drive it — opt out of auto-dismiss.
pytestmark = pytest.mark.no_auto_dismiss


def _require_strict_profile() -> str:
    expected = os.environ.get("EXPECTED_CSP_PROFILE")
    assert expected in STRICT_CSP_PROFILES, (
        "EXPECTED_CSP_PROFILE must be phase2-target or phase3-target. "
        "Run via `make test-e2e-csp CSP_PROFILE=<profile>`."
    )
    return expected


def test_cookie_consent_alpine_survives_strict_csp(page: Page) -> None:
    """Named component + assignment (both ways) + method call, zero CSP violations."""
    _require_strict_profile()
    install_csp_violation_capture(page)

    page.goto(f"{BASE_URL}/cookie-policy/", wait_until="domcontentloaded")

    # Named-component init: if the nonced inline <script> defining cookieConsent()
    # failed to execute under the strict policy, Alpine could not process
    # x-data="cookieConsent()" and this wait would time out — the core
    # inline-removal safety assertion.
    wait_for_alpine(page, "#cookie-consent-banner")

    banner = page.locator("#cookie-consent-banner")
    assert banner.is_visible(), (
        "Cookie banner (x-show=showBanner) did not render under the strict CSP"
    )

    save_btn = banner.locator('button[aria-label="Save cookie preferences"]')
    accept_all = banner.locator('button[aria-label="Accept all cookies"]')

    # Assignment expression -> true: @click="showPreferences = true" reveals panel.
    banner.locator('button[aria-label="Customize cookie preferences"]').click()
    save_btn.wait_for(state="visible", timeout=5000)

    # Assignment expression -> false: @click="showPreferences = false" restores view.
    banner.locator('button[aria-label="Close preferences"]').click()
    accept_all.wait_for(state="visible", timeout=5000)

    # Method-call expression: @click="acceptAll()" persists consent + hides banner.
    accept_all.click()
    page.wait_for_function("() => document.cookie.includes('cookie_consent')")
    consent = next(
        (c for c in page.context.cookies() if c["name"] == "cookie_consent"),
        None,
    )
    assert consent is not None and "accepted_all" in consent["value"], (
        "acceptAll() did not persist the consent cookie under the strict CSP"
    )

    # THE gate: zero CSP violations across the entire Alpine interaction.
    violations = read_csp_violations(page)
    assert violations == [], (
        f"Strict CSP was violated during the Alpine interaction: {violations!r}"
    )
