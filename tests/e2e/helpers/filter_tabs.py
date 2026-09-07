"""Shared behavior assertions for the list-page filter tabs widget (#368).

The component (``shared/ui/templates/components/list_page_filters.html``)
renders TWO tablists — desktop and mobile — both always present in the DOM
with only CSS hiding one. Every helper here therefore scopes to the visible
tablist for interaction, but asserts cross-tablist consistency explicitly:
``switchTab()`` syncs both tablists, while keyboard roving stays inside one.
"""

from playwright.sync_api import Locator, Page, expect

from tests.e2e.helpers.htmx import wait_for_htmx_settle

ACTIVE_TAB_INPUT = "#list-filter-active-tab"


def visible_tablist(page: Page) -> Locator:
    return page.locator('[role="tablist"]:visible')


def visible_tabs(page: Page) -> Locator:
    return visible_tablist(page).locator('[role="tab"]')


def tab_values(page: Page) -> list[str]:
    """The widget's tab values, read from the DOM — never hardcoded."""
    return [
        tab.get_attribute("data-tab-value") or ""
        for tab in visible_tabs(page).all()
    ]


def visible_tab(page: Page, value: str) -> Locator:
    return visible_tablist(page).locator(f'[role="tab"][data-tab-value="{value}"]')


def click_tab(page: Page, value: str) -> None:
    visible_tab(page, value).click()
    wait_for_htmx_settle(page)


def assert_selection_state(page: Page, expected_value: str) -> None:
    """The full post-activation contract, across BOTH tablists.

    Exactly one tab per tablist is selected (so two page-wide — the dual
    tablist duality), both tablists agree on WHICH value is active, roving
    tabindex follows selection, and the hidden input carries the value the
    next HTMX request will send.
    """
    for tablist in page.locator('[role="tablist"]').all():
        selected = tablist.locator('[role="tab"][aria-selected="true"]')
        expect(selected).to_have_count(1)
        assert selected.get_attribute("data-tab-value") == expected_value
        assert selected.get_attribute("tabindex") == "0"
        unselected = tablist.locator('[role="tab"][aria-selected="false"]')
        for tab in unselected.all():
            assert tab.get_attribute("tabindex") == "-1"
    expect(page.locator(ACTIVE_TAB_INPUT)).to_have_value(expected_value)


def assert_panel_integrity(page: Page, content_id: str) -> None:
    """The tabpanel element must survive HTMX swaps with its ARIA intact."""
    panel = page.locator(f"#{content_id}")
    expect(panel).to_be_attached()
    assert panel.get_attribute("role") == "tabpanel"
    assert panel.get_attribute("tabindex") == "0"


def assert_panel_labelled_by_active_tab(page: Page, content_id: str) -> None:
    """aria-labelledby must reference the active tab of the desktop tablist."""
    panel = page.locator(f"#{content_id}")
    labelledby = panel.get_attribute("aria-labelledby")
    assert labelledby, f"#{content_id} has no aria-labelledby"
    referenced = page.locator(f"#{labelledby}")
    assert referenced.count() == 1, (
        f"#{content_id} aria-labelledby={labelledby!r} references "
        f"{referenced.count()} elements"
    )
    assert referenced.get_attribute("aria-selected") == "true"


def text_color(locator: Locator) -> str:
    return locator.evaluate("el => getComputedStyle(el).color")


def hover_neutral(page: Page) -> None:
    """Park the pointer somewhere that cannot hover any tab."""
    page.locator("body").hover(position={"x": 5, "y": 5})


def assert_hover_follows_selection(page: Page, activated: str, deactivated: str) -> None:
    """#368 polish contract, value-free so it survives any styling refactor:

    - Hovering the ACTIVE tab must NOT change its text color (the accent
      holds; the historical bug reverted it to the inactive hover grey).
    - Hovering an INACTIVE tab MUST change its text color (the hover
      affordance exists; the historical bug left an initially-active,
      later-deactivated tab permanently hover-dead).
    """
    active = visible_tab(page, activated)
    inactive = visible_tab(page, deactivated)

    hover_neutral(page)
    active_before = text_color(active)
    active.hover()
    page.wait_for_timeout(100)
    active_after = text_color(active)
    assert active_after == active_before, (
        f"active tab '{activated}' text color changed on hover "
        f"({active_before} -> {active_after}) — hover is overriding the accent"
    )

    hover_neutral(page)
    inactive_before = text_color(inactive)
    inactive.hover()
    page.wait_for_timeout(100)
    inactive_after = text_color(inactive)
    assert inactive_after != inactive_before, (
        f"inactive tab '{deactivated}' text color did not change on hover "
        f"({inactive_before}) — the tab is hover-dead"
    )
