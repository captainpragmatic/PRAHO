"""Behavioral contract of the shared filter tabs widget on the platform (#368).

Exercises the REAL JavaScript state machine (``switchTab``/``handleTabKeydown``
in ``shared/ui/static/js/ui-actions.js``) on the staff tickets page — the
rendering tests in ``tests/tickets/test_ticket_list_rendering.py`` pin source
fragments and cannot catch behavioral regressions.

Scope note: this file owns the WIDGET contract; page-level tickets behavior
stays in test_platform_tickets.py.
"""

from playwright.sync_api import Page, expect

from tests.e2e.helpers import navigate_to_platform_page
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

CONTENT_ID = "tickets-content"
EXPECTED_TAB_COUNT = 5


def _open_tickets(page: Page) -> list[str]:
    assert navigate_to_platform_page(page, "/tickets/", "tickets")
    wait_for_htmx_settle(page)
    # Non-vacuous by construction: empty fixture data must fail here loudly,
    # never skip silently (the pre-#368 tab tests passed vacuously).
    expect(visible_tabs(page)).to_have_count(EXPECTED_TAB_COUNT)
    values = tab_values(page)
    # The "All" tab's value is legitimately "" (no filter) — assert count and
    # uniqueness, not truthiness.
    assert len(set(values)) == EXPECTED_TAB_COUNT, values
    return values


def test_click_activates_tab_and_syncs_both_tablists(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    values = _open_tickets(page)
    target = values[1]

    click_tab(page, target)

    assert_selection_state(page, target)
    assert_panel_integrity(page, CONTENT_ID)
    assert_panel_labelled_by_active_tab(page, CONTENT_ID)


def test_keyboard_navigation_roves_activates_and_wraps(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    values = _open_tickets(page)
    first, last = values[0], values[-1]

    active = page.locator('[role="tablist"]:visible [role="tab"][aria-selected="true"]')
    start = active.get_attribute("data-tab-value")
    start_idx = values.index(start)
    active.focus()

    # ArrowRight: focus AND activation move to the next tab.
    page.keyboard.press("ArrowRight")
    wait_for_htmx_settle(page)
    expected = values[(start_idx + 1) % len(values)]
    focused_value = page.evaluate("document.activeElement.dataset.tabValue")
    assert focused_value == expected
    assert_selection_state(page, expected)

    # End jumps to the last tab.
    page.keyboard.press("End")
    wait_for_htmx_settle(page)
    assert page.evaluate("document.activeElement.dataset.tabValue") == last
    assert_selection_state(page, last)

    # ArrowRight from the last tab wraps to the first.
    page.keyboard.press("ArrowRight")
    wait_for_htmx_settle(page)
    assert page.evaluate("document.activeElement.dataset.tabValue") == first
    assert_selection_state(page, first)

    # ArrowLeft from the first tab wraps back to the last.
    page.keyboard.press("ArrowLeft")
    wait_for_htmx_settle(page)
    assert page.evaluate("document.activeElement.dataset.tabValue") == last
    assert_selection_state(page, last)

    # Home jumps to the first tab.
    page.keyboard.press("Home")
    wait_for_htmx_settle(page)
    assert page.evaluate("document.activeElement.dataset.tabValue") == first
    assert_selection_state(page, first)


def test_tabpanel_attributes_survive_htmx_swap(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    values = _open_tickets(page)

    click_tab(page, values[2])
    assert_panel_integrity(page, CONTENT_ID)
    click_tab(page, values[0])
    assert_panel_integrity(page, CONTENT_ID)
    assert_selection_state(page, values[0])


def test_first_render_labels_the_panel(monitored_staff_page: Page) -> None:
    """The panel must be labelled from first paint, not only after a click."""
    page = monitored_staff_page
    _open_tickets(page)

    assert_panel_labelled_by_active_tab(page, CONTENT_ID)


def test_no_count_badges_on_a_page_without_counts(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    _open_tickets(page)

    expect(page.locator("[data-tab-count]")).to_have_count(0)


def test_hover_styling_follows_selection(monitored_staff_page: Page) -> None:
    """#368 polish: activation must move the hover affordance, not strand it."""
    page = monitored_staff_page
    values = _open_tickets(page)
    initially_active = page.locator(
        '[role="tablist"]:visible [role="tab"][aria-selected="true"]'
    ).get_attribute("data-tab-value")
    target = next(v for v in values if v != initially_active)

    click_tab(page, target)

    assert_hover_follows_selection(page, activated=target, deactivated=initially_active)
