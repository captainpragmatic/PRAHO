"""
Cookie Consent Banner E2E Tests for PRAHO Portal

Tests GDPR cookie consent compliance:
- Banner visibility on first visit
- Accept all / essential only / custom preferences
- Persistence across pages and refreshes
- Re-open from footer link
- Easy withdrawal (GDPR Art. 7(3))
- Cookie policy page accessibility
- Accessible controls (aria-labels, keyboard)
"""

import json
from urllib.parse import unquote

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.helpers import (
    BASE_URL,
    PLATFORM_BASE_URL,
    dismiss_cookie_consent,
    wait_for_alpine,
)

# All tests in this module need the banner visible (opt out of auto-dismiss)
pytestmark = pytest.mark.no_auto_dismiss


def test_banner_shows_on_first_visit(page: Page) -> None:
    """Banner visible on first visit with 3 action buttons, essential toggle disabled."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible(timeout=5000)

    # 3 main buttons: Essential Only, Customize, Accept All
    buttons = banner.locator("button")
    assert buttons.count() >= 3

    # Expand preferences to verify "Always On" badge for essential cookies
    page.locator("#cookie-consent-banner button", has_text="Customize").click()
    page.wait_for_load_state("domcontentloaded")
    always_on = banner.locator("text=Always On")
    expect(always_on).to_be_visible()


def test_accept_all(page: Page) -> None:
    """Banner disappears after Accept All, doesn't reappear on refresh."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible(timeout=5000)

    page.locator("#cookie-consent-banner button", has_text="Accept All").click()
    expect(banner).to_be_hidden(timeout=3000)

    # Verify cookie_consent cookie is set
    cookies = page.context.cookies()
    consent_cookie = next((c for c in cookies if c["name"] == "cookie_consent"), None)
    assert consent_cookie is not None
    assert "accepted_all" in consent_cookie["value"]

    # Refresh — banner should not reappear
    page.reload()
    page.wait_for_load_state("networkidle")
    expect(banner).to_be_hidden()


def test_essential_only(page: Page) -> None:
    """Essential Only sets only essential=true in cookie."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible(timeout=5000)

    page.locator("#cookie-consent-banner button", has_text="Essential Only").click()
    expect(banner).to_be_hidden(timeout=3000)

    cookies = page.context.cookies()
    consent_cookie = next((c for c in cookies if c["name"] == "cookie_consent"), None)
    assert consent_cookie is not None
    assert "accepted_essential" in consent_cookie["value"]


def test_custom_preferences(page: Page) -> None:
    """Customize panel, toggle individual categories, cookie reflects choices."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible(timeout=5000)

    # Click Customize to expand preferences panel
    page.locator("#cookie-consent-banner button", has_text="Customize").click()
    page.wait_for_load_state("domcontentloaded")

    # Click the <label> wrapping the functional toggle (the sr-only checkbox
    # is hidden and its visual sibling div intercepts pointer events)
    functional_label = banner.locator("label").filter(has=page.locator('input[aria-label*="functional" i]'))
    functional_label.click()

    # Save
    page.locator("#cookie-consent-banner button", has_text="Save Preferences").click()
    expect(banner).to_be_hidden(timeout=3000)

    cookies = page.context.cookies()
    consent_cookie = next((c for c in cookies if c["name"] == "cookie_consent"), None)
    assert consent_cookie is not None
    preferences = json.loads(unquote(consent_cookie["value"]))
    assert preferences["status"] == "customized"
    assert preferences["essential"] is True
    assert preferences["functional"] is True
    assert preferences["analytics"] is False
    assert preferences["marketing"] is False
    page.reload()
    page.get_by_role("link", name="Cookie Preferences", exact=True).click()
    expect(banner.locator('input[aria-label*="functional" i]')).to_be_checked()


def test_persists_across_pages(page: Page) -> None:
    """Banner never reappears after acceptance."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    dismiss_cookie_consent(page)

    # Navigate to a different page — banner should stay hidden
    page.goto(f"{BASE_URL}/register/")
    page.wait_for_load_state("networkidle")

    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_hidden()


def test_reopen_from_footer(page: Page) -> None:
    """Footer link reopens preferences."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    dismiss_cookie_consent(page)

    # Verify Cookie Preferences footer link exists
    footer_link = page.locator("a", has_text="Cookie Preferences")
    expect(footer_link).to_be_visible()

    # Call showCookiePreferences via JS (the footer onclick handler calls this;
    # in dev, Django Debug Toolbar overlay intercepts direct clicks)
    page.get_by_role("link", name="Cookie Preferences", exact=True).click()

    # Banner should reappear in preferences mode
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible(timeout=3000)


def test_withdrawal_is_easy(page: Page) -> None:
    """
    Accept all → reopen → disable → save works (GDPR Art. 7(3)).
    Withdrawal must be as easy as giving consent.
    """
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible(timeout=5000)

    # Accept all
    page.locator("#cookie-consent-banner button", has_text="Accept All").click()
    expect(banner).to_be_hidden(timeout=3000)

    # Reopen via showCookiePreferences (the footer onclick calls this;
    # in dev, Django Debug Toolbar overlay intercepts direct link clicks)
    page.get_by_role("link", name="Cookie Preferences", exact=True).click()
    expect(banner).to_be_visible(timeout=3000)

    # Click "Reject All" in preferences via dispatchEvent
    # (the banner is z-50 but debug toolbar may still intercept in headless mode)
    page.locator("#cookie-consent-banner button", has_text="Reject All").dispatch_event("click")
    expect(banner).to_be_hidden(timeout=3000)

    # Verify cookie now shows essential-only
    cookies = page.context.cookies()
    consent_cookie = next((c for c in cookies if c["name"] == "cookie_consent"), None)
    assert consent_cookie is not None
    assert "accepted_essential" in consent_cookie["value"]


def test_accessible(page: Page) -> None:
    """aria-labels present, banner has role=dialog."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible(timeout=5000)

    # Banner has role="dialog"
    assert banner.get_attribute("role") == "dialog"

    # Buttons have aria-labels
    accept_btn = banner.locator("button", has_text="Accept All")
    assert accept_btn.get_attribute("aria-label")

    essential_btn = banner.locator("button", has_text="Essential Only")
    assert essential_btn.get_attribute("aria-label")


def test_cookie_policy_page(page: Page) -> None:
    """/cookie-policy/ loads and describes all 4 categories."""
    # Dismiss banner first since this test focuses on the policy page content
    from tests.e2e.helpers import _dismiss_cookie_consent  # noqa: PLC0415

    _dismiss_cookie_consent(page, BASE_URL)

    page.goto(f"{BASE_URL}/cookie-policy/")
    page.wait_for_load_state("networkidle")

    # Page loads
    expect(page.locator("h1")).to_contain_text("Cookie Policy")

    # All 4 categories described (use heading locators to avoid ambiguous matches)
    expect(page.get_by_role("heading", name="Essential Cookies")).to_be_visible()
    expect(page.get_by_role("heading", name="Functional Cookies")).to_be_visible()
    expect(page.get_by_role("heading", name="Analytics Cookies")).to_be_visible()
    expect(page.get_by_role("heading", name="Marketing Cookies")).to_be_visible()

    # Legal basis documented
    expect(page.locator("text=Legal Basis").first).to_be_visible()


def test_server_recording(page: Page) -> None:
    """Accept All while intercepting network — Platform API returns success."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    wait_for_alpine(page, "#cookie-consent-banner")
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible(timeout=5000)

    # Use expect_response context manager (deterministic, blocks until matched)
    with page.expect_response(
        lambda r: "cookie-consent" in r.url and r.status == 200,
        timeout=5000,
    ) as response_info:
        page.locator("#cookie-consent-banner button", has_text="Accept All").click()

    response = response_info.value
    expect(banner).to_be_hidden(timeout=3000)

    # Verify the Portal proxy endpoint returned success (which means Platform API succeeded)
    data = response.json()
    assert data.get("success") is True, f"Expected success=true from cookie-consent API, got: {data}"


def test_platform_has_no_cookie_banner(page: Page) -> None:
    """Platform (staff-only) should not show a cookie consent banner."""
    page.goto(f"{PLATFORM_BASE_URL}/auth/login/")
    page.wait_for_load_state("networkidle")

    banner = page.locator("#cookie-consent-banner")
    assert banner.count() == 0 or not banner.is_visible(), "Cookie consent banner should not appear on Platform"


def test_consent_history_shows_real_data(account_page) -> None:
    page, _ = account_page
    page.goto(f"{BASE_URL}/cookie-policy/")
    page.get_by_role("link", name="Cookie Preferences", exact=True).click()
    banner = page.locator("#cookie-consent-banner")
    expect(banner).to_be_visible()
    for name in ("functional", "analytics", "marketing"):
        checkbox = banner.locator(f'input[aria-label="Toggle {name} cookies"]')
        if not checkbox.is_checked():
            checkbox.locator("..").click()
        expect(checkbox).to_be_checked()
    with page.expect_response(
        lambda response: "cookie-consent" in response.url and response.request.method == "POST"
    ) as response:
        banner.get_by_role("button", name="Save cookie preferences", exact=True).click()
    assert response.value.status == 200
    assert response.value.json()["success"] is True
    page.goto(f"{BASE_URL}/consent-history/")
    expect(page.locator("#main-content")).to_contain_text("Custom Preferences")
    page.reload()
    expect(page.locator("#main-content")).to_contain_text("Custom Preferences")
