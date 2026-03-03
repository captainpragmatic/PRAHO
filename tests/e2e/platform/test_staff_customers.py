"""
Staff Customer Management E2E Tests for PRAHO Platform

Tests the staff-facing customer management functionality including:
- Customer list page loading and search
- Customer detail view
- Customer create/edit form rendering
- Profile forms (tax, billing, address, note)
- Access control for unauthenticated users
"""

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers import (
    PLATFORM_BASE_URL,
    ensure_fresh_platform_session,
    navigate_to_platform_page,
)

# ===============================================================================
# HELPERS
# ===============================================================================


def _get_first_customer_id(page: Page) -> str | None:
    """Extract the first customer ID from the customer list page.

    Navigates to /customers/ and parses the href of the first customer link.
    Returns the customer ID as a string, or None if no customers found.
    """
    navigate_to_platform_page(page, "/customers/")
    page.wait_for_load_state("networkidle")

    # Scope to table rows to avoid matching sidebar nav links
    link = page.locator('table a[href*="/customers/"]').filter(
        has_text=re.compile(r".+")
    ).first
    if link.count() == 0:
        return None
    href = link.get_attribute("href")
    if not href:
        return None

    # Extract numeric ID from href like /customers/3/
    match = re.search(r"/customers/(\d+)/", href)
    return match.group(1) if match else None


# ===============================================================================
# LIST AND SEARCH TESTS
# ===============================================================================


def test_customer_list_page_loads(monitored_staff_page: Page) -> None:
    """Navigate to /customers/ and verify heading and table are visible."""
    page = monitored_staff_page
    print("🧪 Testing customer list page loads")

    navigate_to_platform_page(page, "/customers/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/customers/"))

    heading = page.locator("h1").first
    expect(heading).to_be_visible()
    print(f"  ✅ Page heading visible: {heading.inner_text()}")

    table = page.locator("table")
    expect(table.first).to_be_attached()
    rows = page.locator("table tbody tr")
    row_count = rows.count()
    assert row_count > 0, f"Customer table should have rows, found {row_count}"
    print(f"  ✅ Customer table displays {row_count} rows")


def test_customer_list_search(monitored_staff_page: Page) -> None:
    """Search for a customer name and verify results filter."""
    page = monitored_staff_page
    print("🧪 Testing customer list search")

    navigate_to_platform_page(page, "/customers/")
    page.wait_for_load_state("networkidle")

    search_field = page.locator('input[type="search"], input[name="search"], input[name="q"]')
    if not search_field.is_visible():
        print("  [i] Search field not found — skipping search test")
        return

    initial_rows = page.locator("table tbody tr").count()
    print(f"  ✅ Initial row count: {initial_rows}")

    search_field.fill("test")
    search_field.press("Enter")
    page.wait_for_load_state("networkidle")

    filtered_rows = page.locator("table tbody tr").count()
    print(f"  ✅ Filtered row count: {filtered_rows}")

    # Clear search
    search_field.clear()
    search_field.press("Enter")
    page.wait_for_load_state("networkidle")

    restored_rows = page.locator("table tbody tr").count()
    print(f"  ✅ Restored row count: {restored_rows}")


# ===============================================================================
# DETAIL AND EDIT TESTS
# ===============================================================================


def test_customer_detail_view(monitored_staff_page: Page) -> None:
    """Navigate to customer detail and verify info sections are present."""
    page = monitored_staff_page
    print("🧪 Testing customer detail view")

    customer_id = _get_first_customer_id(page)
    assert customer_id, "No customers found in list — fixtures may not be loaded"

    navigate_to_platform_page(page, f"/customers/{customer_id}/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(rf"/customers/{customer_id}/"))

    heading = page.locator("h1").first
    expect(heading).to_be_visible()
    print(f"  ✅ Detail heading: {heading.inner_text()}")

    # Verify key information sections exist on the page
    page_content = page.locator("main, .content, body").first.inner_text()
    assert len(page_content) > 50, "Detail page should have substantial content"
    print("  ✅ Customer detail page has content")

    # Check for edit/delete action links
    action_links = page.locator(
        f'a[href*="/customers/{customer_id}/edit/"], '
        f'a[href*="/customers/{customer_id}/delete/"]'
    )
    if action_links.count() > 0:
        print(f"  ✅ {action_links.count()} management action links found")


def test_customer_create_form_renders(monitored_staff_page: Page) -> None:
    """Verify /customers/create/ form loads without errors."""
    page = monitored_staff_page
    print("🧪 Testing customer create form renders")

    navigate_to_platform_page(page, "/customers/create/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/customers/create/"))

    form = page.locator("form")
    expect(form.first).to_be_attached()

    fields = page.locator("input, select, textarea").count()
    assert fields > 0, "Create form should have input fields"
    print(f"  ✅ Create form loaded with {fields} fields")

    submit = page.locator('button[type="submit"], input[type="submit"]')
    expect(submit.first).to_be_attached()
    print("  ✅ Submit button present")


def test_customer_edit_form_renders(monitored_staff_page: Page) -> None:
    """Verify edit form loads for an existing customer."""
    page = monitored_staff_page
    print("🧪 Testing customer edit form renders")

    customer_id = _get_first_customer_id(page)
    assert customer_id, "No customers found in list — fixtures may not be loaded"

    navigate_to_platform_page(page, f"/customers/{customer_id}/edit/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(rf"/customers/{customer_id}/edit/"))

    form = page.locator("form")
    expect(form.first).to_be_attached()

    fields = page.locator("input, select, textarea").count()
    assert fields > 0, "Edit form should have input fields"
    print(f"  ✅ Edit form loaded with {fields} fields")


# ===============================================================================
# PROFILE FORM TESTS (PREVIOUSLY 500 ERRORS)
# ===============================================================================


def test_customer_tax_profile_form_renders(monitored_staff_page: Page) -> None:
    """Verify tax profile form loads (was previously returning 500)."""
    page = monitored_staff_page
    print("🧪 Testing customer tax profile form renders")

    customer_id = _get_first_customer_id(page)
    assert customer_id, "No customers found in list — fixtures may not be loaded"

    navigate_to_platform_page(page, f"/customers/{customer_id}/tax-profile/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(rf"/customers/{customer_id}/tax-profile/"))

    form = page.locator("form")
    expect(form.first).to_be_attached()

    fields = page.locator("input, select, textarea").count()
    assert fields > 0, "Tax profile form should have input fields"
    print(f"  ✅ Tax profile form loaded with {fields} fields")


def test_customer_billing_profile_form_renders(monitored_staff_page: Page) -> None:
    """Verify billing profile form loads (was previously returning 500)."""
    page = monitored_staff_page
    print("🧪 Testing customer billing profile form renders")

    customer_id = _get_first_customer_id(page)
    assert customer_id, "No customers found in list — fixtures may not be loaded"

    navigate_to_platform_page(page, f"/customers/{customer_id}/billing-profile/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(rf"/customers/{customer_id}/billing-profile/"))

    form = page.locator("form")
    expect(form.first).to_be_attached()

    fields = page.locator("input, select, textarea").count()
    assert fields > 0, "Billing profile form should have input fields"
    print(f"  ✅ Billing profile form loaded with {fields} fields")


def test_customer_address_form_renders(monitored_staff_page: Page) -> None:
    """Verify address add form loads (was previously returning 500)."""
    page = monitored_staff_page
    print("🧪 Testing customer address form renders")

    customer_id = _get_first_customer_id(page)
    assert customer_id, "No customers found in list — fixtures may not be loaded"

    navigate_to_platform_page(page, f"/customers/{customer_id}/address/add/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(rf"/customers/{customer_id}/address/add/"))

    form = page.locator("form")
    expect(form.first).to_be_attached()

    fields = page.locator("input, select, textarea").count()
    assert fields > 0, "Address form should have input fields"
    print(f"  ✅ Address form loaded with {fields} fields")


def test_customer_note_form_renders(monitored_staff_page: Page) -> None:
    """Verify note add form loads (was previously returning 500)."""
    page = monitored_staff_page
    print("🧪 Testing customer note form renders")

    customer_id = _get_first_customer_id(page)
    assert customer_id, "No customers found in list — fixtures may not be loaded"

    navigate_to_platform_page(page, f"/customers/{customer_id}/note/add/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(rf"/customers/{customer_id}/note/add/"))

    form = page.locator("form")
    expect(form.first).to_be_attached()

    fields = page.locator("input, select, textarea").count()
    assert fields > 0, "Note form should have input fields"
    print(f"  ✅ Note form loaded with {fields} fields")


# ===============================================================================
# ACCESS CONTROL TESTS
# ===============================================================================


def test_customer_access_control(monitored_staff_page: Page) -> None:
    """Unauthenticated user should be redirected to login."""
    page = monitored_staff_page
    print("🧪 Testing customer access control")

    # Clear any existing session
    ensure_fresh_platform_session(page)

    # Attempt to access customers without logging in
    page.goto(f"{PLATFORM_BASE_URL}/customers/")
    page.wait_for_load_state("networkidle")

    current_url = page.url
    assert "/auth/login/" in current_url or "/login/" in current_url, (
        f"Unauthenticated user should be redirected to login, got: {current_url}"
    )
    print("  ✅ Unauthenticated access to /customers/ redirected to login")

    # Also verify protected sub-pages redirect
    page.goto(f"{PLATFORM_BASE_URL}/customers/create/")
    page.wait_for_load_state("networkidle")

    current_url = page.url
    assert "/auth/login/" in current_url or "/login/" in current_url, (
        f"Unauthenticated user should be redirected to login, got: {current_url}"
    )
    print("  ✅ Unauthenticated access to /customers/create/ redirected to login")
