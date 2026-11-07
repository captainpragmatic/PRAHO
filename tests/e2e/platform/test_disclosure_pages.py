"""In a real browser, the disclosures follow the page's own state, and the audit chevrons still turn (#821).

The disclosure only reads and flips state the page already holds; the region's x-show stays its owner. So the
settings menu still starts open on a desktop and closed on a phone, and the server form's advanced options still
start closed. Enter and Space toggle it, aria-expanded follows, and the labels say what a press will do. The audit
log's expand buttons are icon_buttons now, and audit-fragments.js still finds and turns their `.chevron-icon`.

The Virtualmin restore form has the same disclosure on the same `showAdvanced` state as the server form, but it lists
backups from object storage, which the E2E stack doesn't have, so the server form stands in for it here.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL
from tests.e2e.helpers.csp import ensure_csp_capture, read_csp_violations

DESKTOP = {"width": 1280, "height": 900}
PHONE = {"width": 390, "height": 844}
# Below the lg breakpoint; the server form's breadcrumb already overflows a phone, which is not this control.
NARROW = {"width": 768, "height": 1024}


def test_the_settings_menu_starts_open_on_a_desktop_and_closed_on_a_phone(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    page.set_viewport_size(DESKTOP)
    page.goto(f"{PLATFORM_BASE_URL}/settings/")
    expect(page.locator("#settings-nav")).to_be_visible()
    expect(page.locator('button[aria-controls="settings-nav"]')).to_be_hidden()

    page.set_viewport_size(PHONE)
    page.goto(f"{PLATFORM_BASE_URL}/settings/")
    toggle = page.locator('button[aria-controls="settings-nav"]')
    expect(toggle).to_be_visible()
    expect(toggle).to_have_attribute("aria-expanded", "false")
    expect(page.locator("#settings-nav")).to_be_hidden()
    toggle.focus()
    page.keyboard.press("Enter")
    expect(toggle).to_have_attribute("aria-expanded", "true")
    expect(page.locator("#settings-nav")).to_be_visible()
    page.keyboard.press(" ")
    expect(toggle).to_have_attribute("aria-expanded", "false")
    expect(page.locator("#settings-nav")).to_be_hidden()
    assert read_csp_violations(page) == []


def test_the_server_form_s_advanced_options_start_closed_and_toggle(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    for viewport in (DESKTOP, NARROW):
        page.set_viewport_size(viewport)
        page.goto(f"{PLATFORM_BASE_URL}/provisioning/virtualmin/servers/create/")
        toggle = page.locator('button[aria-controls="server-advanced-options"]')
        region = page.locator("#server-advanced-options")
        expect(toggle).to_have_attribute("aria-expanded", "false")
        expect(toggle.get_by_text("Show Advanced Options")).to_be_visible()
        expect(toggle.get_by_text("Hide Advanced Options")).to_be_hidden()
        expect(region).to_be_hidden()
        toggle.focus()
        page.keyboard.press(" ")
        expect(toggle).to_have_attribute("aria-expanded", "true")
        expect(toggle.get_by_text("Hide Advanced Options")).to_be_visible()
        expect(toggle.get_by_text("Show Advanced Options")).to_be_hidden()
        expect(region).to_be_visible()
        page.keyboard.press("Enter")
        expect(toggle).to_have_attribute("aria-expanded", "false")
        expect(region).to_be_hidden()
    assert read_csp_violations(page) == []


def test_the_audit_log_s_expand_chevron_still_turns(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    page.goto(f"{PLATFORM_BASE_URL}/audit/logs/")
    expand = page.get_by_role("button", name="View Details").first
    expect(expand).to_be_visible()
    chevron = expand.locator(".chevron-icon")
    expect(chevron).to_have_count(1)
    expand.click()
    expect(chevron).to_have_attribute("style", "transform: rotate(180deg);")
    expand.click()
    expect(chevron).to_have_attribute("style", "transform: rotate(0deg);")
    assert read_csp_violations(page) == []
