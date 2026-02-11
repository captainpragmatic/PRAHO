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

from playwright.sync_api import Page, expect

from tests.e2e.utils import (
    BASE_URL,
    dismiss_cookie_consent,
)


def test_banner_shows_on_first_visit(page: Page) -> None:
    """Banner visible on first visit with 3 action buttons, essential toggle disabled."""
    page.goto(f"{BASE_URL}/login/")
    banner = page.locator('#cookie-consent-banner')
    expect(banner).to_be_visible(timeout=5000)

    # 3 main buttons: Essential Only, Customize, Accept All
    buttons = banner.locator('button')
    assert buttons.count() >= 3

    # Essential cookies should show "Always On" badge (not a toggle)
    always_on = banner.locator('text=Always On')
    expect(always_on).to_be_visible()


def test_accept_all(page: Page) -> None:
    """Banner disappears after Accept All, doesn't reappear on refresh."""
    page.goto(f"{BASE_URL}/login/")
    banner = page.locator('#cookie-consent-banner')
    expect(banner).to_be_visible(timeout=5000)

    page.locator('#cookie-consent-banner button', has_text='Accept All').click()
    expect(banner).to_be_hidden(timeout=3000)

    # Verify cookie_consent cookie is set
    cookies = page.context.cookies()
    consent_cookie = next((c for c in cookies if c['name'] == 'cookie_consent'), None)
    assert consent_cookie is not None
    assert 'accepted_all' in consent_cookie['value']

    # Refresh — banner should not reappear
    page.reload()
    page.wait_for_load_state('networkidle')
    expect(banner).to_be_hidden()


def test_essential_only(page: Page) -> None:
    """Essential Only sets only essential=true in cookie."""
    page.goto(f"{BASE_URL}/login/")
    banner = page.locator('#cookie-consent-banner')
    expect(banner).to_be_visible(timeout=5000)

    page.locator('#cookie-consent-banner button', has_text='Essential Only').click()
    expect(banner).to_be_hidden(timeout=3000)

    cookies = page.context.cookies()
    consent_cookie = next((c for c in cookies if c['name'] == 'cookie_consent'), None)
    assert consent_cookie is not None
    assert 'accepted_essential' in consent_cookie['value']


def test_custom_preferences(page: Page) -> None:
    """Customize panel, toggle individual categories, cookie reflects choices."""
    page.goto(f"{BASE_URL}/login/")
    banner = page.locator('#cookie-consent-banner')
    expect(banner).to_be_visible(timeout=5000)

    # Click Customize
    page.locator('#cookie-consent-banner button', has_text='Customize').click()

    # Should see preferences panel with toggle checkboxes
    functional_toggle = banner.locator('input[type="checkbox"]').first
    expect(functional_toggle).to_be_visible()

    # Enable functional, leave others off
    functional_toggle.check()

    # Save
    page.locator('#cookie-consent-banner button', has_text='Save Preferences').click()
    expect(banner).to_be_hidden(timeout=3000)

    cookies = page.context.cookies()
    consent_cookie = next((c for c in cookies if c['name'] == 'cookie_consent'), None)
    assert consent_cookie is not None
    assert 'customized' in consent_cookie['value']


def test_persists_across_pages(page: Page) -> None:
    """Banner never reappears after acceptance."""
    page.goto(f"{BASE_URL}/login/")
    dismiss_cookie_consent(page)

    # Navigate to another page
    page.goto(f"{BASE_URL}/cookie-policy/")
    page.wait_for_load_state('networkidle')

    banner = page.locator('#cookie-consent-banner')
    expect(banner).to_be_hidden()


def test_reopen_from_footer(page: Page) -> None:
    """Footer link reopens preferences."""
    page.goto(f"{BASE_URL}/login/")
    dismiss_cookie_consent(page)

    # Find and click "Cookie Preferences" in footer
    footer_link = page.locator('a', has_text='Cookie Preferences')
    expect(footer_link).to_be_visible()
    footer_link.click()

    # Banner should reappear in preferences mode
    banner = page.locator('#cookie-consent-banner')
    expect(banner).to_be_visible(timeout=3000)


def test_withdrawal_is_easy(page: Page) -> None:
    """
    Accept all → reopen → disable → save works (GDPR Art. 7(3)).
    Withdrawal must be as easy as giving consent.
    """
    page.goto(f"{BASE_URL}/login/")
    banner = page.locator('#cookie-consent-banner')
    expect(banner).to_be_visible(timeout=5000)

    # Accept all
    page.locator('#cookie-consent-banner button', has_text='Accept All').click()
    expect(banner).to_be_hidden(timeout=3000)

    # Reopen via footer
    page.locator('a', has_text='Cookie Preferences').click()
    expect(banner).to_be_visible(timeout=3000)

    # Click "Reject All" in preferences
    page.locator('#cookie-consent-banner button', has_text='Reject All').click()
    expect(banner).to_be_hidden(timeout=3000)

    # Verify cookie now shows essential-only
    cookies = page.context.cookies()
    consent_cookie = next((c for c in cookies if c['name'] == 'cookie_consent'), None)
    assert consent_cookie is not None
    assert 'accepted_essential' in consent_cookie['value']


def test_accessible(page: Page) -> None:
    """aria-labels present, banner has role=dialog."""
    page.goto(f"{BASE_URL}/login/")
    banner = page.locator('#cookie-consent-banner')
    expect(banner).to_be_visible(timeout=5000)

    # Banner has role="dialog"
    assert banner.get_attribute('role') == 'dialog'

    # Buttons have aria-labels
    accept_btn = banner.locator('button', has_text='Accept All')
    assert accept_btn.get_attribute('aria-label')

    essential_btn = banner.locator('button', has_text='Essential Only')
    assert essential_btn.get_attribute('aria-label')


def test_cookie_policy_page(page: Page) -> None:
    """/cookie-policy/ loads and describes all 4 categories."""
    page.goto(f"{BASE_URL}/cookie-policy/")
    page.wait_for_load_state('networkidle')

    # Page loads
    expect(page.locator('h1')).to_contain_text('Cookie Policy')

    # All 4 categories described
    expect(page.locator('text=Essential Cookies')).to_be_visible()
    expect(page.locator('text=Functional Cookies')).to_be_visible()
    expect(page.locator('text=Analytics Cookies')).to_be_visible()
    expect(page.locator('text=Marketing Cookies')).to_be_visible()

    # Legal basis documented
    expect(page.locator('text=Legal Basis')).to_be_visible()
