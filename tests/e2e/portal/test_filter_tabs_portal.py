"""Behavioral contract of the shared filter tabs widget on the portal (#368).

The services page is the one consumer that passes count badges, so this file
carries the badge contract on top of the shared widget behavior. Badges are
rendered server-side only — HTMX swaps the content div and never re-renders
the tabs, so badge values must stay UNCHANGED after a tab click (asserting an
"update" here would pin impossible behavior).

Scope note: this file owns the WIDGET contract; page-level services behavior
stays in test_customer_services.py.
"""

from playwright.sync_api import Page, expect

from tests.e2e.helpers.constants import BASE_URL
from tests.e2e.helpers.filter_tabs import (
    assert_hover_follows_selection,
    assert_panel_integrity,
    assert_panel_labelled_by_active_tab,
    assert_selection_state,
    click_tab,
    tab_values,
    visible_tabs,
)
from tests.e2e.helpers.htmx import wait_for_htmx_settle

CONTENT_ID = "services-content"
EXPECTED_TAB_COUNT = 8


def _open_services(page: Page) -> list[str]:
    page.goto(f"{BASE_URL}/services/")
    wait_for_htmx_settle(page)
    # Non-vacuous by construction — see the platform twin.
    expect(visible_tabs(page)).to_have_count(EXPECTED_TAB_COUNT)
    values = tab_values(page)
    # The "All" tab's value is legitimately "" (no filter) — assert count and
    # uniqueness, not truthiness.
    assert len(set(values)) == EXPECTED_TAB_COUNT, values
    return values


def _visible_badges(page: Page) -> dict[str, str]:
    badges = {}
    for tab in visible_tabs(page).all():
        badge = tab.locator("[data-tab-count]")
        if badge.count():
            badges[tab.get_attribute("data-tab-value") or ""] = badge.inner_text().strip()
    return badges


def test_click_activates_tab_and_syncs_both_tablists(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    values = _open_services(page)
    target = values[1]

    click_tab(page, target)

    assert_selection_state(page, target)
    assert_panel_integrity(page, CONTENT_ID)
    assert_panel_labelled_by_active_tab(page, CONTENT_ID)


def test_keyboard_navigation_roves_activates_and_wraps(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    values = _open_services(page)
    first, last = values[0], values[-1]

    active = page.locator('[role="tablist"]:visible [role="tab"][aria-selected="true"]')
    active.focus()

    page.keyboard.press("End")
    wait_for_htmx_settle(page)
    assert page.evaluate("document.activeElement.dataset.tabValue") == last
    assert_selection_state(page, last)

    page.keyboard.press("ArrowRight")
    wait_for_htmx_settle(page)
    assert page.evaluate("document.activeElement.dataset.tabValue") == first
    assert_selection_state(page, first)

    page.keyboard.press("ArrowLeft")
    wait_for_htmx_settle(page)
    assert page.evaluate("document.activeElement.dataset.tabValue") == last
    assert_selection_state(page, last)

    page.keyboard.press("Home")
    wait_for_htmx_settle(page)
    assert page.evaluate("document.activeElement.dataset.tabValue") == first
    assert_selection_state(page, first)


def test_first_render_labels_the_panel(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _open_services(page)

    assert_panel_labelled_by_active_tab(page, CONTENT_ID)


def test_count_badges_render_and_stay_stable_across_swaps(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    values = _open_services(page)

    badges = _visible_badges(page)
    # Loud failure over vacuous pass: no badges means the platform summary API
    # returned no counts under e2e fixtures — seed data (make fixtures) rather
    # than letting this test silently skip its purpose.
    assert badges, "no count badges rendered — seed fixture data (make fixtures)"
    for value, text in badges.items():
        assert text.isdigit(), f"badge for tab '{value}' is not numeric: {text!r}"

    click_tab(page, values[1])

    assert _visible_badges(page) == badges, (
        "badges changed after a tab click — HTMX never re-renders the tabs, "
        "so any change means the widget contract shifted"
    )


def test_hover_styling_follows_selection(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    values = _open_services(page)
    initially_active = page.locator(
        '[role="tablist"]:visible [role="tab"][aria-selected="true"]'
    ).get_attribute("data-tab-value")
    target = next(v for v in values if v != initially_active)

    click_tab(page, target)

    assert_hover_follows_selection(page, activated=target, deactivated=initially_active)
