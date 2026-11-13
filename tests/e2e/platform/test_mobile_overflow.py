"""On a phone, staff pages fit the screen; on a keyboard, the backup codes' copy buttons can be seen.

Each page here used to be wider than a phone screen, so the whole page scrolled sideways: a long setting key on the
billing settings, the server form's breadcrumb, and the audit and GDPR date filters (two date inputs that would not
shrink). The backup codes' copy buttons only appear on hover, so a keyboard user focused an invisible button.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pyotp
from playwright.sync_api import Browser, Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL, PLATFORM_LOGIN_URL

SETUP_PATH = "/auth/mfa/setup/totp/"


def _fits(page: Page, path: str, width: int) -> None:
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{PLATFORM_BASE_URL}{path}")
    page.wait_for_load_state("networkidle")
    scroll, view = page.evaluate("[document.documentElement.scrollWidth, document.documentElement.clientWidth]")
    assert scroll <= view, f"{path} at {width}px is {scroll}px wide"


def test_a_long_setting_key_fits_a_phone(monitored_staff_page: Page) -> None:
    _fits(monitored_staff_page, "/settings/billing/", 390)


def test_the_server_form_breadcrumb_fits_a_phone(monitored_staff_page: Page) -> None:
    _fits(monitored_staff_page, "/provisioning/virtualmin/servers/create/", 390)


def test_the_audit_and_gdpr_date_filters_fit_a_phone(monitored_staff_page: Page) -> None:
    _fits(monitored_staff_page, "/audit/logs/", 375)
    _fits(monitored_staff_page, "/audit/gdpr_management/", 375)


def test_the_desktop_layout_is_unchanged(monitored_staff_page: Page) -> None:
    """At desktop width the breadcrumb is one line and the date inputs share one row, as before."""
    page = monitored_staff_page
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{PLATFORM_BASE_URL}/provisioning/virtualmin/servers/create/")
    items = page.locator('nav[aria-label="Breadcrumb"] li')
    tops = {round(box["y"]) for box in (items.nth(i).bounding_box() for i in range(items.count())) if box}
    assert len(tops) == 1, tops
    page.goto(f"{PLATFORM_BASE_URL}/audit/logs/")
    start, end = page.locator('input[name="start_date"]'), page.locator('input[name="end_date"]')
    start_box, end_box = start.bounding_box(), end.bounding_box()
    assert start_box and end_box and round(start_box["y"]) == round(end_box["y"])


def test_a_focused_backup_code_copy_button_is_visible(browser: Browser, e2e_scenario: Callable[[str], Any]) -> None:
    accounts = e2e_scenario("staff_mfa")
    context = browser.new_context(viewport={"width": 1280, "height": 900})
    page = context.new_page()
    try:
        page.goto(f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}")
        page.locator('input[name="email"]').fill(accounts["staff_email"])
        page.locator('input[name="password"]').fill(accounts["password"])
        page.locator('button[type="submit"]').click()
        page.wait_for_url(lambda url: PLATFORM_LOGIN_URL not in url)
        page.goto(f"{PLATFORM_BASE_URL}{SETUP_PATH}")
        secret = (page.locator("#secret-key").text_content() or "").strip()
        page.locator('input[name="token"]').fill(pyotp.TOTP(secret).now())
        page.locator('input[name="password"]').fill(accounts["password"])
        page.get_by_role("button", name="Verify & Enable MFA").click()
        copy = page.locator('#backup-codes-grid button[data-invoke="copyCodeAction"]').first
        expect(copy).to_be_attached()
        page.mouse.move(0, 0)
        assert copy.evaluate("el => getComputedStyle(el).opacity") == "0", "hidden until hover or focus"
        copy.focus()
        page.keyboard.press("Shift+Tab")
        page.keyboard.press("Tab")  # keyboard focus, so :focus-visible applies
        expect(copy).to_be_focused()
        page.wait_for_function("el => getComputedStyle(el).opacity === '1'", arg=copy.element_handle(), timeout=3000)
    finally:
        context.close()
