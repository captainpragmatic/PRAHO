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

import pytest
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
    link = page.locator('table a[href*="/customers/"]').filter(has_text=re.compile(r".+")).first
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


def test_customer_row_navigates_via_delegated_dispatcher(monitored_staff_page: Page) -> None:
    """The migrated clickable row (data-action='navigate') must navigate via platform-actions.js,
    and the nested copy button (data-action='copy') must NOT navigate — proving the #284
    inline-handler migration works end-to-end with the real dispatcher loaded."""
    page = monitored_staff_page
    navigate_to_platform_page(page, "/customers/")
    page.wait_for_load_state("networkidle")

    row = page.locator("tr[data-action='navigate']").first
    if row.count() == 0:
        print("  [i] No clickable customer rows seeded — skipping dispatcher navigation check")
        pytest.fail("Required E2E step unavailable: row.count() == 0")

    expected = row.get_attribute("data-href")
    assert expected and "/customers/" in expected, f"row data-href unexpected: {expected}"

    # A nested copy button must claim its own click (closest() scoping) — clicking it does NOT navigate.
    copy_btn = row.locator("button[data-action='copy']").first
    if copy_btn.count() > 0 and copy_btn.is_visible():
        copy_btn.click()
        page.wait_for_timeout(300)
        assert "/customers/" in page.url and page.url.rstrip("/").endswith("customers"), (
            f"copy button wrongly navigated to {page.url}"
        )
        print("  ✅ Copy button did not trigger row navigation")

    # Clicking the row navigates through the dispatcher.
    row.click()
    page.wait_for_load_state("networkidle")
    assert re.search(r"/customers/\d+/", page.url), f"row click did not navigate to detail: {page.url}"
    print(f"  ✅ Row navigated via dispatcher to {page.url}")


def test_customer_list_search(monitored_staff_page: Page, e2e_baseline) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/customers/")
    search = page.locator('input[name="q"]:visible')
    search.fill(e2e_baseline["customers"][1]["name"])
    search.press("Enter")
    expect(page.locator("tbody tr[data-href]")).to_have_count(1)
    expect(page.locator("tbody")).to_contain_text(e2e_baseline["customers"][1]["name"])
    expect(page.locator("tbody")).not_to_contain_text(e2e_baseline["customers"][0]["name"])
    search.fill("unmatched-company-name-zzzz")
    search.press("Enter")
    expect(page.locator("tbody tr[data-href]")).to_have_count(0)
    search.fill("")
    search.press("Enter")
    expect(page.locator("tbody tr[data-href]").first).to_be_visible()


# ===============================================================================
# DETAIL AND EDIT TESTS
# ===============================================================================


def test_customer_detail_view(monitored_staff_page: Page, e2e_baseline) -> None:
    page = monitored_staff_page
    customer = e2e_baseline["customers"][0]
    page.goto(f"{PLATFORM_BASE_URL}/customers/{customer['id']}/")
    expect(page.locator("main")).to_contain_text(customer["name"])
    expect(page.locator("main")).to_contain_text(customer["email"])
    expect(page.locator(f'a[href="/customers/{customer["id"]}/edit/"]').first).to_be_visible()


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

    expect(page.locator('[name="company_name"]')).to_be_visible()

    expect(page.locator('[name="email"]')).to_be_visible()

    expect(page.locator('[name="address_line1"]')).to_be_visible()


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

    expect(page.locator('[name="name"]')).to_be_visible()

    expect(page.locator('[name="company_name"]')).to_be_visible()

    expect(page.locator('[name="primary_email"]')).to_be_visible()


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

    expect(page.locator('[name="cui"]')).to_be_visible()

    expect(page.locator('[name="vat_number"]')).to_be_visible()


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

    expect(page.locator('[name="payment_terms"]')).to_be_visible()

    expect(page.locator('[name="preferred_currency"]')).to_be_visible()


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

    expect(page.locator('[name="address_line1"]')).to_be_visible()

    expect(page.locator('[name="city"]')).to_be_visible()

    expect(page.locator('[name="postal_code"]')).to_be_visible()


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

    expect(page.locator('[name="title"]')).to_be_visible()

    expect(page.locator('[name="content"]')).to_be_visible()


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
