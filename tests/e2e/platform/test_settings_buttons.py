"""In a real browser, the settings buttons work through the button component's Alpine bindings.

Rendering tests prove the attributes; only the vendored @alpinejs/csp build under the page's CSP proves the
expressions run: Replace opens the secret input, Save enables only once something is typed, the icon-only cancel
closes it, an edit shows the unsaved bar with its translated label from data-*, and Discard clears it. Nothing is saved.
"""

from __future__ import annotations

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL


def test_a_secrets_replace_save_and_cancel_work(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/settings/stripe/")
    row = page.locator("[x-data^='settingsSecretRow']").first
    row.get_by_role("button", name=re.compile("Replace")).click()
    value = row.locator("input[type='password']")
    expect(value).to_be_visible()
    save = row.get_by_role("button", name="Save", exact=True)
    expect(save).to_be_disabled()
    value.fill("sk_test_not_saved")
    expect(save).to_be_enabled()
    row.get_by_role("button", name="Cancel").click()
    expect(value).to_be_hidden()


def test_an_edit_shows_the_unsaved_bar_and_discard_clears_it(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/settings/billing/")
    field = page.locator("input[data-setting-field][type='number']").first
    field.fill(str(int(field.input_value() or "0") + 1))
    field.dispatch_event("input")
    field.dispatch_event("change")
    bar_label = page.locator("[x-text='unsavedLabel']")
    expect(bar_label).to_have_text(re.compile(r"^1 "))
    page.get_by_role("button", name="Discard", exact=True).click()
    expect(bar_label).to_be_hidden()
