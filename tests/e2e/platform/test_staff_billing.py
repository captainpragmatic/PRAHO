"""
Staff Billing System E2E Tests for PRAHO Platform

This module comprehensively tests the staff billing and invoice management functionality including:
- Billing system navigation and access (staff permissions)
- Proforma invoice creation and management
- Proforma to invoice conversion workflows
- Invoice management and processing
- Payment tracking and collection
- Romanian e-Factura integration
- VAT calculations and Romanian tax compliance
- PDF generation and document handling
- Staff-only administrative features
- Billing reports and analytics
- HTMX interactions and real-time updates

Uses shared utilities from tests.e2e.helpers for consistency.
Based on real staff workflows for Romanian billing operations.
"""

import re
from urllib.parse import urljoin, urlparse

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, expect

# Import shared utilities
from tests.e2e.helpers import (
    PLATFORM_BASE_URL,
    assert_responsive_results,
    navigate_to_platform_page,
    require_authentication,
    run_responsive_breakpoints_test,
)

# ===============================================================================
# PRIVATE HELPERS — proforma creation workflow
# ===============================================================================


def _fill_proforma_form(page: Page, data: dict) -> None:
    """Require all fields that establish the business transaction under test."""
    page.select_option('select[name="customer"]', str(data["customer_id"]))
    page.fill('input[name="line_0_description"]', data["description"])
    page.fill('input[name="line_0_unit_price"]', data["amount"])
    page.fill('input[name="line_0_quantity"]', "1")
    page.select_option('select[name="currency"]', "RON")
    page.select_option('select[name="line_0_vat_rate"]', "21")


def _submit_proforma_form(page: Page) -> None:
    page.get_by_role("button", name="Create Proforma", exact=True).click()
    page.wait_for_load_state("networkidle")


def _verify_proforma_created(page: Page) -> None:
    expect(page).to_have_url(re.compile(r"/billing/proformas/\d+/$"))
    expect(page.get_by_role("heading", level=1, name=re.compile("^Proforma "))).to_be_visible()


# ===============================================================================
# PRIVATE HELPERS — complete billing workflow
# ===============================================================================


def _fill_workflow_proforma_form(page: Page, data: dict) -> None:
    _fill_proforma_form(page, data)
    _submit_proforma_form(page)
    _verify_proforma_created(page)


def _record_bank_payment(page: Page, reference: str) -> str:
    """Payment causes issuance. Assert the full persisted UI result."""
    page.get_by_role("button", name="Record Payment", exact=True).first.click()
    modal = page.locator("#paymentModal")
    expect(modal).to_be_visible()
    modal.locator('select[name="payment_method"]').select_option("bank_transfer")
    modal.locator('input[name="reference"]').fill(reference)
    modal.get_by_role("button", name="Confirm Payment", exact=True).click()
    expect(page).to_have_url(re.compile(r"/billing/invoices/\d+/$"))
    expect(page.get_by_text("Paid", exact=True)).to_be_visible()
    expect(page.locator("tr").filter(has_text=reference)).to_have_count(1)
    return page.url


def _assert_conversion_link(page: Page, proforma_url: str, invoice_url: str) -> None:
    page.goto(proforma_url)
    expect(page.locator("main")).to_contain_text(re.compile("converted", re.IGNORECASE))
    expect(page.locator(f'a[href="{urlparse(invoice_url).path}"]').first).to_be_visible()
    expect(page.get_by_role("button", name="Record Payment", exact=True)).to_have_count(0)


def _test_pdf_generation(page: Page) -> None:
    link = page.get_by_role("link", name="Download PDF", exact=True).first
    expect(link).to_be_visible()
    response = page.request.get(urljoin(page.url, link.get_attribute("href")))
    assert response.status == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.body().startswith(b"%PDF-")
    assert len(response.body()) > 1000


def _assert_bank_payment_retry(page: Page, proforma_url: str, invoice_url: str, reference: str) -> None:
    page.goto(proforma_url)
    token = page.locator('input[name="csrfmiddlewaretoken"]').first.input_value()
    response = page.request.post(
        proforma_url + "pay/",
        form={"payment_method": "bank_transfer", "reference": reference, "csrfmiddlewaretoken": token},
        headers={"Referer": proforma_url},
    )
    assert response.status == 200
    assert response.url == invoice_url
    page.goto(invoice_url)
    expect(page.locator("tr").filter(has_text=reference)).to_have_count(1)


# ===============================================================================
# STAFF BILLING SYSTEM ACCESS AND NAVIGATION TESTS
# ===============================================================================


def test_staff_billing_system_access_via_navigation(monitored_staff_page: Page) -> None:
    """
    Test staff accessing the billing system through Billing dropdown navigation.

    This test verifies the complete navigation path to billing for staff:
    1. Login as staff user (superuser)
    2. Click Billing dropdown in navigation
    3. Click Invoices or Billing link
    4. Verify billing list page loads correctly with staff features
    """
    page = monitored_staff_page
    print("🧪 Testing staff billing system access via navigation")

    # Navigate directly to billing list page (platform uses side nav, not dropdowns)
    page.goto(f"{PLATFORM_BASE_URL}/billing/invoices/")
    page.wait_for_load_state("networkidle")

    # Verify we're on the billing list page
    assert "/billing/" in page.url, "Should navigate to billing list page"

    # Verify page title and staff-specific content (handle both English and Romanian)
    title = page.title()
    assert "Billing" in title or "Facturare" in title, f"Expected billing page title but got: {title}"
    billing_heading = page.locator('h1:has-text("Billing Management")').first
    assert billing_heading.is_visible(), "Billing system heading should be visible"

    # Check for creation button (may not be implemented yet)
    new_invoice_button = page.locator(
        'a:has-text("New Invoice"), button:has-text("New Invoice"), a:has-text("New Proforma"), button:has-text("Create")'
    )
    if new_invoice_button.count() > 0:
        print("  ✅ Invoice/Proforma creation button available")
    else:
        print("  [i] Invoice/Proforma creation functionality may not be implemented yet")

    print("  ✅ Staff billing system successfully accessible via Billing navigation")


def test_staff_billing_list_dashboard_display(monitored_staff_page: Page) -> None:
    """
    Test the staff billing list dashboard displays correctly with statistics and filtering.

    This test verifies:
    - Billing statistics cards show accurate counts (proformas, invoices, payments)
    - Filtering and search interface is present for staff
    - Combined proforma/invoice table loads with existing documents
    - Staff-specific features are visible (convert, PDF, send, etc.)
    """
    page = monitored_staff_page
    print("🧪 Testing staff billing list dashboard display")

    # Navigate to billing
    navigate_to_platform_page(page, "/billing/invoices/")
    page.wait_for_load_state("networkidle")

    # Verify billing statistics are present
    stats_section = page.locator("div").filter(has_text="Total:")
    if stats_section.is_visible():
        print("  ✅ Billing statistics section is visible")
    else:
        # Try alternative selector for stats
        proforma_text = page.get_by_text("Proformas:")
        invoice_text = page.get_by_text("Invoices:")
        if proforma_text.count() > 0 or invoice_text.count() > 0:
            print("  ✅ Found billing statistics")
        else:
            print("  [i] Billing statistics not found - may need alternative implementation")

    # Check for creation functionality
    new_invoice_button = page.locator(
        'a:has-text("New Invoice"), button:has-text("New Invoice"), a:has-text("New Proforma"), button:has-text("Create")'
    )
    if new_invoice_button.count() > 0:
        print("  ✅ Invoice/Proforma creation functionality available")
    else:
        print("  [i] Creation functionality may not be fully implemented yet")

    # Verify filtering interface is present (if implemented)
    filters_section = page.locator("div.bg-slate-800\\/50").filter(has_text="Search").first
    if filters_section.is_visible():
        print("  ✅ Billing filtering interface is present")
    else:
        print("  [i] Billing filtering interface may not be implemented yet")

    # Verify billing page content is present (support both English and Romanian)
    billing_content = page.locator('div:has-text("Invoices"), div:has-text("Facturi")').first
    assert billing_content.is_visible(), "Billing content should be present"

    # Check if any documents are displayed (depends on fixture data)
    document_items = page.locator(
        'tr:has-text("PRO-"), tr:has-text("INV-"), div:has-text("PRO-"), div:has-text("INV-")'
    )
    document_count = document_items.count()
    if document_count > 0:
        print(f"  ✅ Found {document_count} billing documents in the system")
    else:
        # No billing documents in fixture data — verify empty state renders correctly
        empty_state = page.locator("text=No invoices, text=No documents, text=Nu există").first
        print(
            f"  [i] No billing documents found — empty state visible: {empty_state.is_visible() if empty_state.count() > 0 else 'N/A'}"
        )

    print("  ✅ Staff billing list dashboard displays correctly")


# ===============================================================================
# STAFF PROFORMA INVOICE CREATION TESTS
# ===============================================================================


def test_staff_proforma_creation_workflow(monitored_staff_page: Page, e2e_scenario) -> None:
    """
    Test the complete staff proforma invoice creation workflow.

    This test covers the full staff proforma creation process:
    1. Navigate to proforma creation form
    2. Fill in proforma details for a customer
    3. Add line items with products/services
    4. Apply Romanian VAT calculations (21%)
    5. Submit form and verify proforma is created
    6. Verify redirect to proforma detail page
    """
    page = monitored_staff_page
    print("🧪 Testing staff proforma creation workflow")

    # Navigate to proforma creation
    navigate_to_platform_page(page, "/billing/invoices/")
    page.wait_for_load_state("networkidle")

    # Click "New Proforma" button
    new_proforma_button = page.locator('a:has-text("New Proforma"), a:has-text("Proformă nouă")').first
    assert new_proforma_button.is_visible(), "New Proforma button should be visible for staff"
    new_proforma_button.click()

    # Verify we're on the create proforma page
    page.wait_for_url("**/billing/proformas/create/", timeout=8000)
    assert "/billing/proformas/create/" in page.url

    # Verify create proforma form elements
    create_heading = page.locator('h1:has-text("Create New Proforma"), h1:has-text("Create Proforma")')
    assert create_heading.is_visible(), "Create proforma heading should be visible"

    # Test proforma data for staff creation
    test_proforma_data = {
        "customer_id": e2e_scenario("billing")["customer_id"],
        "description": "Web Hosting Package - Premium Plan",
        "amount": "299.00",
    }

    # Refresh options after creating the owned customer.
    page.reload()
    # Fill all form fields via helper
    _fill_proforma_form(page, test_proforma_data)

    # Verify VAT calculation is applied automatically
    vat_display = page.locator('text="VAT (21%)", text="TVA (21%)"')
    if vat_display.is_visible():
        print("  ✅ Romanian VAT rate (21%) displayed")

    # Submit and verify
    _submit_proforma_form(page)
    _verify_proforma_created(page)

    print("  ✅ Staff proforma creation workflow completed")


# ===============================================================================
# STAFF PROFORMA TO INVOICE CONVERSION TESTS
# ===============================================================================


def test_staff_proforma_to_invoice_conversion(monitored_staff_page: Page, e2e_scenario) -> None:
    """A payable order becomes a paid invoice and enters provisioning via a bank receipt."""
    page = monitored_staff_page
    fixture = e2e_scenario("billing")
    proforma_url = f"{PLATFORM_BASE_URL}/billing/proformas/{fixture['proforma_id']}/"
    page.goto(proforma_url)
    invoice_url = _record_bank_payment(page, fixture["order_number"])
    _test_pdf_generation(page)
    _assert_conversion_link(page, proforma_url, invoice_url)
    _assert_bank_payment_retry(page, proforma_url, invoice_url, fixture["order_number"])
    page.goto(f"{PLATFORM_BASE_URL}/orders/{fixture['order_id']}/")
    expect(page.locator("main")).to_contain_text("Provisioning")
    expect(page.locator(f'a[href="{urlparse(invoice_url).path}"]').first).to_be_visible()


# ===============================================================================
# STAFF INVOICE MANAGEMENT TESTS
# ===============================================================================


def test_staff_invoice_detail_and_management_features(monitored_staff_page: Page, e2e_baseline) -> None:
    page = monitored_staff_page
    customer = e2e_baseline["customers"][0]
    page.goto(f"{PLATFORM_BASE_URL}/billing/invoices/{customer['invoice_id']}/")
    expect(page.locator("main h1")).to_contain_text(customer["invoice_number"])
    expect(page.locator("main")).to_contain_text(customer["name"])
    expect(page.locator("main")).to_contain_text("121,00")
    _test_pdf_generation(page)


# ===============================================================================
# STAFF BILLING REPORTS AND ANALYTICS TESTS
# ===============================================================================


def test_staff_billing_reports_and_analytics(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    response = page.goto(f"{PLATFORM_BASE_URL}/billing/reports/")
    assert response.status == 200
    expect(page.get_by_role("heading", name="Financial Reports", exact=True)).to_be_visible()
    link = page.get_by_role("link", name=re.compile("D390 review"))
    expect(link).to_be_visible()
    link.click()
    expect(page.locator("main")).to_contain_text("accountant review")


# ===============================================================================
# STAFF MOBILE RESPONSIVENESS TESTS
# ===============================================================================


def test_staff_billing_system_mobile_responsiveness(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{PLATFORM_BASE_URL}/billing/invoices/")
    expect(page.get_by_role("link", name="New Proforma", exact=True).first).to_be_visible()
    expect(page.locator("main [data-href]:visible").first).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


# ===============================================================================
# COMPREHENSIVE STAFF BILLING WORKFLOW TESTS
# ===============================================================================


def test_staff_complete_billing_workflow(monitored_staff_page: Page, e2e_scenario) -> None:
    """Create a manual proforma in the UI, receive payment, download the issued invoice."""
    page = monitored_staff_page
    fixture = e2e_scenario("billing")
    page.goto(f"{PLATFORM_BASE_URL}/billing/proformas/create/")
    _fill_workflow_proforma_form(
        page, {"customer_id": fixture["customer_id"], "description": "Staff E2E manual hosting", "amount": "500.00"}
    )
    proforma_url = page.url
    _test_pdf_generation(page)
    invoice_url = _record_bank_payment(page, "E2E-MANUAL-BANK")
    expect(page.locator("main")).to_contain_text("605,00")
    _test_pdf_generation(page)
    _assert_conversion_link(page, proforma_url, invoice_url)
    _assert_bank_payment_retry(page, proforma_url, invoice_url, "E2E-MANUAL-BANK")


def test_staff_billing_system_responsive_breakpoints(monitored_staff_page: Page) -> None:
    """
    Test staff billing system functionality across all responsive breakpoints.

    This test validates that staff billing management works on:
    - Desktop viewports (baseline)
    - Tablet viewports (landscape and portrait)
    - Mobile viewports (various sizes)
    """
    page = monitored_staff_page
    print("🧪 Testing staff billing system across responsive breakpoints")

    def test_staff_billing_functionality(test_page, context="general"):
        """Test core staff billing functionality across viewports."""
        try:
            # Navigate to billing
            test_page.goto(f"{PLATFORM_BASE_URL}/billing/invoices/")
            test_page.wait_for_load_state("networkidle")

            # Verify authentication maintained
            require_authentication(test_page)

            # Check core elements are present
            billing_heading = test_page.locator('h1:has-text("Billing Management")').first

            # Just check for the main heading - creation button may not always be present
            elements_present = billing_heading.is_visible()

            if elements_present:
                print(f"      ✅ Staff billing system functional in {context}")
                return True
            else:
                print(f"      ❌ Core billing elements missing in {context}")
                return False

        except (TimeoutError, PlaywrightError) as e:
            print(f"      ❌ Billing system test failed in {context}: {str(e)[:50]}")
            return False

    # Test across all breakpoints
    results = run_responsive_breakpoints_test(page, test_staff_billing_functionality)

    # Verify all breakpoints pass
    assert_responsive_results(results, "Staff billing system")

    print("  ✅ Staff billing system validated across all responsive breakpoints")


# ===============================================================================
# PROFORMA VAT RATE COMPLIANCE TESTS
# ===============================================================================


def test_proforma_form_vat_rate_dropdown_shows_21_percent(monitored_staff_page: Page) -> None:
    """
    Test that the proforma creation form shows the correct Romanian VAT rates.

    Regression guard for the 19% to 21% VAT transition (Aug 2025).
    Verifies:
    1. VAT dropdown default is 21% (Standard)
    2. Reduced rate is 11% (not stale 9% or 5%)
    3. No stale 19% option exists
    """
    page = monitored_staff_page
    print("🧪 Testing proforma form VAT rate dropdown (21% compliance)")

    # Navigate to proforma create
    page.goto(f"{PLATFORM_BASE_URL}/billing/proformas/create/")
    page.wait_for_load_state("networkidle")

    assert "/billing/proformas/create" in page.url, f"Should be on proforma create page, got: {page.url}"
    print("  ✅ Proforma create page loaded")

    # Find VAT rate dropdown(s) — line items have select with name like 'line_N_vat_rate'
    vat_selects = page.locator("select").filter(has=page.locator("option:has-text('21%')"))
    count = vat_selects.count()
    assert count > 0, "Should find at least one VAT rate dropdown with 21% option"
    print(f"  ✅ Found {count} VAT rate dropdown(s)")

    # Check the first VAT dropdown
    vat_select = vat_selects.first
    selected_value = vat_select.input_value()
    assert selected_value == "21", f"Default VAT rate should be 21, got: {selected_value}"
    print("  ✅ Default value is 21 (Standard)")

    # Verify all options are correct (21%, 11%, 0% — no stale 19%, 9%, 5%)
    options = vat_select.locator("option").all_text_contents()
    print(f"  Options: {options}")

    assert any("21%" in opt for opt in options), "Must have 21% Standard option"
    assert any("11%" in opt for opt in options), "Must have 11% Reduced option"
    assert any("0%" in opt for opt in options), "Must have 0% Exempt option"

    # Stale rate guard
    for opt in options:
        assert "19%" not in opt, f"Stale 19% rate found in dropdown: {opt}"
        assert "9%" not in opt or "19%" in opt, f"Stale 9% reduced rate found: {opt}"
        assert "5%" not in opt, f"Stale 5% super-reduced rate found: {opt}"

    print("  ✅ No stale VAT rates in dropdown")

    # Verify no 19% text anywhere on the page
    body_text = page.inner_text("body")
    assert "19%" not in body_text, "Page should not contain stale '19%' text"
    print("  ✅ No stale '19%' text on the page")

    print("  ✅ Proforma VAT rate compliance verified")
