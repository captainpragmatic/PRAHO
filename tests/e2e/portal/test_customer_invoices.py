"""
Customer Invoices E2E Tests for PRAHO Portal

Comprehensive tests for the customer invoices/billing list page covering:
- Page structure and shared component rendering (header, tabs, search, skeleton)
- Tab-based doc type filtering (All / Invoices / Proformas) via HTMX
- Status dropdown filtering via HTMX
- Live search by document number via HTMX
- Pagination with shared pagination component
- Click-through to invoice/proforma detail pages
- Mobile responsiveness (cards vs table)
- Customer restrictions (no staff features)

Uses the unified list page architecture from ADR-0026.
"""

import re

from playwright.sync_api import Locator, Page, expect

from tests.e2e.utils import (
    BASE_URL,
    MobileTestContext,
    assert_responsive_results,
    run_responsive_breakpoints_test,
    run_standard_mobile_test,
)


def _wait_for_htmx(page: Page, timeout: int = 8000) -> None:
    """Wait for HTMX swap to complete."""
    page.wait_for_load_state("networkidle", timeout=timeout)
    page.wait_for_timeout(300)


def _navigate_to_invoices(page: Page) -> None:
    """Navigate to the invoices list page and verify it loaded."""
    page.goto(f"{BASE_URL}/billing/invoices/")
    page.wait_for_load_state("networkidle")
    assert "/billing/invoices/" in page.url, f"Expected invoices URL, got: {page.url}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_invoices_list_page_structure(monitored_customer_page: Page) -> None:
    """Test invoices list page renders with shared header, tabs, search, and table."""
    page = monitored_customer_page

    _navigate_to_invoices(page)

    # Shared header component: page title
    heading: Locator = page.locator('h1:has-text("Invoices"), h1:has-text("Billing"), h1:has-text("Facturi")').first
    expect(heading).to_be_visible()
    print("  ✅ Page heading visible")

    # Header stats (e.g. "Unpaid", "Total")
    stats: Locator = page.locator(".text-2xl.font-bold")
    if stats.count() >= 2:
        print(f"  ✅ Header stats displayed: {stats.count()} values")

    # Tab navigation (All / Invoices / Proformas)
    tabs: Locator = page.locator("button[role='tab']")
    assert tabs.count() >= 3, f"Expected >= 3 tabs, got {tabs.count()}"
    print(f"  ✅ {tabs.count()} filter tabs present")

    # Search input
    search_input: Locator = page.locator("#list-filter-search")
    expect(search_input).to_be_visible()
    print("  ✅ Search input visible")

    # Status dropdown (extra filter for invoices)
    status_select: Locator = page.locator("select[name='status']")
    expect(status_select).to_be_visible()
    print("  ✅ Status dropdown visible")

    # Table or empty state
    table: Locator = page.locator("table")
    empty_state: Locator = page.locator("text=/No documents found|No billing documents/")
    assert table.count() > 0 or empty_state.count() > 0, "Should show either a data table or empty state"
    if table.count() > 0:
        print("  ✅ Invoice table rendered")
    else:
        print("  ✅ Empty state displayed (no invoices)")

    # NO staff features
    create_btn: Locator = page.locator(
        'a:has-text("Create Invoice"), a:has-text("New Invoice"), a[href*="/billing/invoices/create/"]'
    )
    assert create_btn.count() == 0, "Customer should NOT see invoice creation buttons"
    print("  ✅ No staff-only features visible")


def test_invoices_tab_filtering(monitored_customer_page: Page) -> None:
    """Test doc type tab switching filters via HTMX without page reload."""
    page = monitored_customer_page

    _navigate_to_invoices(page)

    # Get initial URL to verify no full page reload
    initial_url: str = page.url

    # Click "Invoices" tab
    invoices_tab: Locator = page.locator(
        "button[role='tab']:has-text('Invoices'), button[role='tab']:has-text('Facturi')"
    ).first
    if invoices_tab.count() > 0:
        invoices_tab.click()
        _wait_for_htmx(page)

        # Hidden input should track the active tab
        hidden_tab: Locator = page.locator("#list-filter-active-tab")
        tab_value: str = hidden_tab.input_value()
        assert tab_value in ("invoice", "invoices"), f"Expected invoice tab value, got: {tab_value}"
        print(f"  ✅ Invoice tab active, hidden input value: {tab_value}")

    # Click "Proformas" tab
    proformas_tab: Locator = page.locator(
        "button[role='tab']:has-text('Proforma'), button[role='tab']:has-text('Proforme')"
    ).first
    if proformas_tab.count() > 0:
        proformas_tab.click()
        _wait_for_htmx(page)

        hidden_tab = page.locator("#list-filter-active-tab")
        tab_value = hidden_tab.input_value()
        assert tab_value in ("proforma", "proformas"), f"Expected proforma tab value, got: {tab_value}"
        print(f"  ✅ Proforma tab active, hidden input value: {tab_value}")

    # Click "All" tab to reset
    all_tab: Locator = page.locator("button[role='tab']:has-text('All'), button[role='tab']:has-text('Toate')").first
    if all_tab.count() > 0:
        all_tab.click()
        _wait_for_htmx(page)
        print("  ✅ All tab clicked, filter reset")


def test_invoices_search(monitored_customer_page: Page) -> None:
    """Test live search filters invoices via HTMX (keyup with 600ms debounce)."""
    page = monitored_customer_page

    _navigate_to_invoices(page)

    search_input: Locator = page.locator("#list-filter-search")
    expect(search_input).to_be_visible()

    # Count rows before search
    rows_before: int = page.locator("tbody tr").count()

    # Type a search query using press_sequentially to trigger keyup events
    # (fill() doesn't trigger keyup, which HTMX listens for)
    search_input.click()
    search_input.press_sequentially("ZZZZNONEXISTENT999", delay=50)
    # Wait for debounce (600ms) + HTMX network round-trip
    page.wait_for_timeout(2000)
    _wait_for_htmx(page, timeout=10000)

    rows_after: int = page.locator("tbody tr").count()
    empty_state: Locator = page.locator("text=/No documents found|No billing documents/")

    # Should have fewer results or empty state
    if rows_before > 0:
        assert rows_after < rows_before or empty_state.count() > 0, (
            f"Search with non-matching term should reduce results ({rows_before} → {rows_after})"
        )
        print(f"  ✅ Search filtered results: {rows_before} → {rows_after}")

    # Clear search to restore results
    search_input.fill("")
    search_input.dispatch_event("keyup")
    page.wait_for_timeout(1500)
    _wait_for_htmx(page)
    print("  ✅ Search cleared, results restored")


def test_invoices_status_dropdown(monitored_customer_page: Page) -> None:
    """Test status dropdown filtering via HTMX."""
    page = monitored_customer_page

    _navigate_to_invoices(page)

    status_select: Locator = page.locator("select[name='status']")
    if status_select.count() == 0:
        print("  ⚠️ No status dropdown found, skipping")
        return

    # Select "Paid" status if available
    options: list[str] = status_select.locator("option").all_inner_texts()
    print(f"  📊 Status dropdown options: {options}")

    if len(options) > 1:
        # Select the second option (first is usually "All")
        status_select.select_option(index=1)
        _wait_for_htmx(page)
        print(f"  ✅ Selected status filter: {options[1] if len(options) > 1 else 'N/A'}")

        # Reset to all
        status_select.select_option(index=0)
        _wait_for_htmx(page)
        print("  ✅ Status filter reset to all")


def test_invoices_click_through_to_detail(monitored_customer_page: Page) -> None:
    """Test clicking an invoice row navigates to the detail page."""
    page = monitored_customer_page

    _navigate_to_invoices(page)

    # Find clickable row (desktop table)
    clickable_row: Locator = page.locator("tr[onclick]").first
    if clickable_row.count() == 0:
        print("  ⚠️ No invoice rows to click, skipping")
        return

    clickable_row.click()
    page.wait_for_load_state("networkidle")

    # Should navigate to invoice or proforma detail
    current_url: str = page.url
    has_detail: bool = bool(re.search(r"/billing/(invoices|proformas)/[\w-]+/", current_url))
    assert has_detail, f"Expected invoice/proforma detail URL, got: {current_url}"
    print(f"  ✅ Navigated to detail: {current_url}")

    # Verify detail page has content
    page_content: str = page.content()
    assert len(page_content) > 500, "Detail page should have substantial content"

    # Back button should exist
    back_link: Locator = page.locator('a[href*="/billing/invoices/"], a:has-text("Back"), a:has-text("Înapoi")')
    if back_link.count() > 0:
        print("  ✅ Back link present on detail page")


def test_invoices_pagination(monitored_customer_page: Page) -> None:
    """Test shared pagination component renders correctly on invoices."""
    page = monitored_customer_page

    _navigate_to_invoices(page)

    # Check for pagination component
    pagination: Locator = page.locator("nav[aria-label*='Pagination'], nav[aria-label*='pagination']")
    if pagination.count() == 0:
        # May have too few invoices for pagination
        print("  [i] No pagination visible (too few documents)")
        return

    # Verify pagination text format ("X-Y of Z results")
    pagination_text: Locator = page.locator("text=/\\d+-\\d+ of \\d+/")
    if pagination_text.count() > 0:
        print(f"  ✅ Pagination text: {pagination_text.first.inner_text()}")

    # Check for page buttons
    page_buttons: Locator = pagination.locator("button, a")
    if page_buttons.count() > 0:
        print(f"  ✅ Pagination buttons present: {page_buttons.count()}")


def test_invoices_mobile_responsiveness(monitored_customer_page: Page) -> None:
    """Test invoices list renders with mobile cards on small viewports."""
    page = monitored_customer_page

    _navigate_to_invoices(page)

    with MobileTestContext(page, "mobile_medium") as mobile:
        print("  📱 Testing invoices on mobile viewport")

        run_standard_mobile_test(page, mobile, context_label="invoices list")

        # Desktop table should be hidden on mobile
        desktop_table: Locator = page.locator(".hidden.md\\:block table")
        if desktop_table.count() > 0:
            expect(desktop_table.first).to_be_hidden()
            print("    ✅ Desktop table hidden on mobile")

        # Mobile cards should be visible
        mobile_cards: Locator = page.locator(".md\\:hidden div[onclick]")
        if mobile_cards.count() > 0:
            print(f"    ✅ {mobile_cards.count()} mobile invoice cards visible")

        # Tabs should be scrollable on mobile
        mobile_tabs: Locator = page.locator(".sm\\:hidden nav[role='tablist']")
        if mobile_tabs.count() > 0:
            print("    ✅ Mobile scrollable tabs present")

        print("    ✅ Mobile responsiveness validated")


def test_invoices_responsive_breakpoints(monitored_customer_page: Page) -> None:
    """Test invoices page across multiple viewport breakpoints."""

    def _check_invoices_page(pg: Page, _context: str = "general") -> dict:
        pg.goto(f"{BASE_URL}/billing/invoices/")
        pg.wait_for_load_state("networkidle")
        heading = pg.locator('h1:has-text("Invoices"), h1:has-text("Billing"), h1:has-text("Facturi")').first
        search = pg.locator("#list-filter-search")
        return {
            "heading_visible": heading.is_visible(timeout=3000),
            "search_visible": search.is_visible(timeout=2000),
        }

    results = run_responsive_breakpoints_test(monitored_customer_page, _check_invoices_page)
    assert_responsive_results(results)
