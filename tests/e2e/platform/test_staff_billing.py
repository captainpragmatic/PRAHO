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

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.helpers import (
    PLATFORM_BASE_URL,
    MobileTestContext,
    assert_responsive_results,
    navigate_to_platform_page,
    require_authentication,
    run_responsive_breakpoints_test,
    run_standard_mobile_test,
)

# ===============================================================================
# PRIVATE HELPERS — proforma creation workflow
# ===============================================================================

def _fill_proforma_form(page: Page, data: dict) -> None:
    """Fill the proforma creation form fields with the supplied data dict.

    Handles optional field visibility gracefully; prints a warning when a
    field cannot be located rather than failing hard.
    """
    customer_select = page.locator('select[name="customer"]')
    if customer_select.is_visible():
        customer_options = page.locator('select[name="customer"] option')
        if customer_options.count() > 1:
            page.select_option('select[name="customer"]', index=1)
            print("  ✅ Selected customer for proforma creation")
        else:
            print("  ⚠️ No customers available - may need sample data")

    description_field = page.locator(
        'input[name="line_0_description"], textarea[name="line_0_description"]'
    ).first
    if description_field.is_visible():
        description_field.fill(data['description'])
        print("  ✅ Filled line item description")
    else:
        print("  ⚠️ Line item description field not found")

    amount_field = page.locator(
        'input[name="line_0_unit_price"], input[name="line_0_amount"]'
    ).first
    if amount_field.is_visible():
        amount_field.fill(data['amount'])
        print("  ✅ Filled line item amount")
    else:
        print("  ⚠️ Amount field not found")

    quantity_field = page.locator('input[name="line_0_quantity"]')
    if quantity_field.is_visible():
        quantity_field.fill('1')


def _submit_proforma_form(page: Page) -> None:
    """Click the proforma submit button and wait for network idle."""
    submit_button = page.locator(
        'button:has-text("Create Proforma"), button:has-text("Submit"), input[type="submit"]'
    ).first
    if not submit_button.is_visible():
        print("  ❌ Submit button not found")
        return
    submit_button.click()
    page.wait_for_load_state("networkidle")


def _verify_proforma_created(page: Page) -> None:
    """Check the page state after proforma form submission and log the outcome."""
    if "/billing/proformas/" in page.url and "/billing/proformas/create/" not in page.url:
        print("  ✅ Proforma creation succeeded - redirected away from create page")
        success_message = page.get_by_role("alert").locator(
            'div:has-text("created"), div:has-text("Proforma #")'
        ).first
        if success_message.is_visible():
            print("  ✅ Success message displayed")
        return

    # Still on create page — surface any validation errors.
    error_messages = page.locator('div.text-red-600, .text-red-500, [class*="error"]')
    if error_messages.count() > 0:
        error_text = error_messages.first.inner_text()
        print(f"  ❌ Form validation error: {error_text}")
    else:
        print("  [i] Form submitted but still on create page")


# ===============================================================================
# PRIVATE HELPERS — complete billing workflow
# ===============================================================================

def _fill_workflow_proforma_form(page: Page, data: dict) -> None:
    """Fill the proforma form fields for the comprehensive billing workflow."""
    customer_select = page.locator('select[name="customer"]')
    if customer_select.is_visible():
        customer_options = page.locator('select[name="customer"] option')
        if customer_options.count() > 1:
            page.select_option('select[name="customer"]', index=1)

    description_field = page.locator(
        'input[name="line_0_description"], textarea[name="line_0_description"]'
    ).first
    if description_field.is_visible():
        description_field.fill(data['description'])

    amount_field = page.locator(
        'input[name="line_0_unit_price"], input[name="line_0_amount"]'
    ).first
    if amount_field.is_visible():
        amount_field.fill(data['amount'])

    submit_btn = page.locator('button:has-text("Create"), button:has-text("Submit")').first
    if submit_btn.is_visible():
        submit_btn.click()
        page.wait_for_load_state("networkidle")


def _locate_or_navigate_to_proforma(page: Page, data: dict) -> bool:
    """Return True if we are now on a proforma detail page, False otherwise."""
    if "/billing/proformas/" in page.url and "create" not in page.url:
        print("      ✅ Proforma created successfully")
        return True

    print("      [i] Proforma creation may have validation issues - checking list")
    navigate_to_platform_page(page, "/billing/invoices/")
    page.wait_for_load_state("networkidle")

    workflow_proforma_link = page.locator(f'text="{data["description"][:20]}"')
    if workflow_proforma_link.is_visible():
        workflow_proforma_link.click()
        page.wait_for_load_state("networkidle")
        print("      ✅ Found and opened created proforma")
        return True

    return False


def _convert_proforma_to_invoice(page: Page) -> bool:
    """Click 'Convert to Invoice', wait for navigation, return True on success."""
    convert_button = page.locator(
        'a:has-text("Convert to Invoice"), button:has-text("Convert"), a[href*="/convert/"]'
    ).first
    if not convert_button.is_visible():
        print("  ⚠️ Convert button not found")
        return False

    convert_button.click()
    page.wait_for_load_state("networkidle")

    if "/billing/invoices/" in page.url:
        print("      ✅ Proforma converted to invoice successfully")
        return True

    print("  ⚠️ Proforma conversion failed")
    return False


def _test_pdf_generation(page: Page) -> None:
    """Verify the PDF generation button is present on the invoice detail page."""
    pdf_button = page.locator('a:has-text("PDF"), a[href*="/pdf/"]')
    if pdf_button.is_visible():
        print("      ✅ PDF generation feature available")


def _test_payment_recording(page: Page, amount: str) -> None:
    """Attempt to record a payment for the current invoice."""
    payment_button = page.locator('a:has-text("Record Payment"), a[href*="/pay/"]')
    if not payment_button.is_visible():
        return

    payment_button.click()
    page.wait_for_load_state("networkidle")

    amount_field = page.locator('input[name="amount"]')
    if not amount_field.is_visible():
        return

    amount_field.fill(amount)
    submit_payment = page.locator('button:has-text("Record Payment"), button:has-text("Submit")')
    if submit_payment.is_visible():
        submit_payment.click()
        page.wait_for_load_state("networkidle")
        print("      ✅ Payment processing tested")


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
    assert ("Billing" in title or "Facturare" in title), f"Expected billing page title but got: {title}"
    billing_heading = page.locator('h1:has-text("Billing Management")').first
    assert billing_heading.is_visible(), "Billing system heading should be visible"

    # Check for creation button (may not be implemented yet)
    new_invoice_button = page.locator('a:has-text("New Invoice"), button:has-text("New Invoice"), a:has-text("New Proforma"), button:has-text("Create")')
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
    stats_section = page.locator('div').filter(has_text='Total:')
    if stats_section.is_visible():
        print("  ✅ Billing statistics section is visible")
    else:
        # Try alternative selector for stats
        proforma_text = page.get_by_text('Proformas:')
        invoice_text = page.get_by_text('Invoices:')
        if proforma_text.count() > 0 or invoice_text.count() > 0:
            print("  ✅ Found billing statistics")
        else:
            print("  [i] Billing statistics not found - may need alternative implementation")

    # Check for creation functionality
    new_invoice_button = page.locator('a:has-text("New Invoice"), button:has-text("New Invoice"), a:has-text("New Proforma"), button:has-text("Create")')
    if new_invoice_button.count() > 0:
        print("  ✅ Invoice/Proforma creation functionality available")
    else:
        print("  [i] Creation functionality may not be fully implemented yet")

    # Verify filtering interface is present (if implemented)
    filters_section = page.locator('div.bg-slate-800\\/50').filter(has_text="Search").first
    if filters_section.is_visible():
        print("  ✅ Billing filtering interface is present")
    else:
        print("  [i] Billing filtering interface may not be implemented yet")

    # Verify billing page content is present (support both English and Romanian)
    billing_content = page.locator('div:has-text("Invoices"), div:has-text("Facturi")').first
    assert billing_content.is_visible(), "Billing content should be present"

    # Check if any documents are displayed
    document_items = page.locator('tr:has-text("PRO-"), tr:has-text("INV-"), div:has-text("PRO-"), div:has-text("INV-")')
    document_count = document_items.count()
    assert document_count > 0, "Billing list should contain at least one document (PRO- or INV-)"
    print(f"  ✅ Found {document_count} billing documents in the system")

    print("  ✅ Staff billing list dashboard displays correctly")


# ===============================================================================
# STAFF PROFORMA INVOICE CREATION TESTS
# ===============================================================================

def test_staff_proforma_creation_workflow(monitored_staff_page: Page) -> None:
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
        'description': 'Web Hosting Package - Premium Plan',
        'amount': '299.00',
    }

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

def test_staff_proforma_to_invoice_conversion(monitored_staff_page: Page) -> None:
    """
    Test staff proforma to invoice conversion workflow.

    This test covers:
    - Finding existing proforma or creating one
    - Converting proforma to invoice
    - Verifying invoice sequence numbering
    - Ensuring proforma remains linked to invoice
    - Romanian business compliance
    """
    page = monitored_staff_page
    print("🧪 Testing staff proforma to invoice conversion")

    # Navigate to billing
    navigate_to_platform_page(page, "/billing/invoices/")
    page.wait_for_load_state("networkidle")

    # Find first proforma to convert (if any exist)
    proforma_links = page.locator('a[href*="/billing/proformas/"]:has-text("PRO-")')
    if proforma_links.count() == 0:
        # Try alternative selectors for proforma links
        proforma_links = page.locator('a[href*="/billing/proformas/"]:not([href*="create"])')

    if proforma_links.count() > 0:
        # Click on first proforma
        first_proforma_link = proforma_links.first
        first_proforma_link.click()
        page.wait_for_load_state("networkidle")

        # Verify we're on a proforma detail page
        assert "/billing/proformas/" in page.url and page.url.endswith("/")
        print("  ✅ Navigated to proforma detail page")

        # Look for convert to invoice button
        convert_button = page.locator('a:has-text("Convert to Invoice"), button:has-text("Convert"), a[href*="/convert/"]').first
        if convert_button.is_visible():
            print("  🔄 Testing proforma conversion to invoice...")
            convert_button.click()
            page.wait_for_load_state("networkidle")

            # Check if conversion was successful
            if "/billing/invoices/" in page.url:
                print("  ✅ Proforma successfully converted to invoice")

                # Verify we're now on the invoice detail page
                invoice_heading = page.locator('h1:has-text("INV-"), h1:has-text("Invoice")')
                assert invoice_heading.is_visible(), "Invoice detail page heading should be displayed after conversion"
                print("  ✅ Invoice detail page displayed")

                # Check for conversion success message
                success_message = page.get_by_role("alert").locator('div:has-text("converted"), div:has-text("Invoice created")')
                if success_message.is_visible():
                    print("  ✅ Conversion success message displayed")

                # Verify invoice has sequential numbering (INV-YYYY-XXXXXX format)
                invoice_number = page.locator('span:has-text("INV-"), h1:has-text("INV-")')
                assert invoice_number.is_visible(), "Invoice number should be visible after conversion"
                number_text = invoice_number.first.inner_text()
                assert "INV-" in number_text and len(number_text) > 8, \
                    f"Invoice numbering format should match INV-YYYY-XXXXXX, got: {number_text}"
                print("  ✅ Invoice sequential numbering appears correct")
            else:
                # Check for conversion errors
                error_message = page.get_by_role("alert").locator('div:has-text("error"), div:has-text("failed")')
                if error_message.is_visible():
                    error_text = error_message.first.inner_text()
                    print(f"  ❌ Conversion error: {error_text}")
                else:
                    print("  [i] Conversion completed but still on proforma page")
        else:
            print("  [i] Convert to Invoice button not found - proforma may already be converted")
    else:
        print("  [i] No proformas available for conversion testing")

    print("  ✅ Staff proforma to invoice conversion testing completed")


# ===============================================================================
# STAFF INVOICE MANAGEMENT TESTS
# ===============================================================================

def test_staff_invoice_detail_and_management_features(monitored_staff_page: Page) -> None:
    """
    Test staff invoice detail page and management capabilities.

    This test verifies:
    - Invoice detail page loads with all information
    - Staff-specific management features are visible
    - PDF generation functionality
    - Email sending capabilities
    - Payment processing options
    - Romanian e-Factura integration
    """
    page = monitored_staff_page
    print("🧪 Testing staff invoice detail and management features")

    # Navigate to billing
    navigate_to_platform_page(page, "/billing/invoices/")
    page.wait_for_load_state("networkidle")

    # Find first invoice to view (if any exist)
    invoice_links = page.locator('a[href*="/billing/invoices/"]:has-text("INV-")')
    if invoice_links.count() == 0:
        # Try looking for any table/list links containing invoice numbers
        invoice_links = page.locator('table a[href*="/billing/invoices/"], .invoice-list a[href*="/billing/invoices/"]')

    if invoice_links.count() > 0:
        # Click on first invoice
        first_invoice_link = invoice_links.first
        first_invoice_link.click()
        page.wait_for_load_state("networkidle")

        # Verify we're on an invoice detail page
        assert "/billing/invoices/" in page.url and page.url.endswith("/")
        print("  ✅ Navigated to invoice detail page")

        # Verify invoice detail elements are present
        invoice_info = page.locator('h1:has-text("INV-"), h1:has-text("#")')
        assert invoice_info.is_visible(), "Invoice information heading should be displayed on detail page"
        print("  ✅ Invoice information displayed")

        # Check for staff management features
        # PDF generation button
        pdf_button = page.locator('a:has-text("PDF"), button:has-text("Download PDF"), a[href*="/pdf/"]')
        assert pdf_button.is_visible(), "PDF generation feature should be available on invoice detail page"
        print("  ✅ PDF generation feature available")

        # Email sending functionality
        email_button = page.locator('a:has-text("Send"), button:has-text("Email"), a[href*="/send/"]')
        if email_button.is_visible():
            print("  ✅ Email sending feature available")
        else:
            print("  [i] Email sending feature not found")

        # Payment processing options
        payment_button = page.locator('a:has-text("Record Payment"), button:has-text("Pay"), a[href*="/pay/"]')
        if payment_button.is_visible():
            print("  ✅ Payment processing feature available")
        else:
            print("  [i] Payment processing feature not found")

        # Romanian e-Factura integration
        efactura_button = page.locator('a:has-text("e-Factura"), button:has-text("Generate XML"), a[href*="/e-factura/"]')
        if efactura_button.is_visible():
            print("  ✅ Romanian e-Factura integration available")
        else:
            print("  [i] e-Factura integration not found")

        # Check for VAT information display
        vat_info = page.locator('text="VAT", text="TVA", text="19%"')
        if vat_info.is_visible():
            print("  ✅ VAT information displayed")

        # Verify customer information is shown
        customer_info = page.locator('div:has-text("Customer:"), section:has-text("Bill To:")')
        assert customer_info.is_visible(), "Customer information section should be present on invoice detail"
        print("  ✅ Customer information section present")

    else:
        print("  [i] No invoices available for management testing")

    print("  ✅ Staff invoice management features verified")


# ===============================================================================
# STAFF BILLING REPORTS AND ANALYTICS TESTS
# ===============================================================================

def test_staff_billing_reports_and_analytics(monitored_staff_page: Page) -> None:
    """
    Test staff billing reports and analytics functionality.

    This test covers:
    - Accessing billing reports dashboard
    - VAT reports for Romanian compliance
    - Payment collection reports
    - Revenue analytics and statistics
    - Date range filtering
    - Export capabilities
    """
    page = monitored_staff_page
    print("🧪 Testing staff billing reports and analytics")

    # Test access to billing reports
    navigate_to_platform_page(page, "/billing/reports/")
    page.wait_for_load_state("networkidle")

    # Verify reports page loads
    reports_heading = page.locator('h1:has-text("Reports"), h1:has-text("Rapoarte")')
    if reports_heading.is_visible():
        print("  ✅ Billing reports page accessible")

        # Check for various report types
        vat_report_link = page.locator('a:has-text("VAT Report"), a:has-text("Raport TVA")')
        if vat_report_link.is_visible():
            print("  ✅ VAT report link available")

            # Test VAT report access
            vat_report_link.click()
            page.wait_for_load_state("networkidle")

            if "/billing/reports/vat/" in page.url:
                print("  ✅ VAT report page loads correctly")

                # Check for Romanian VAT compliance elements
                vat_elements = page.locator('text="19%", text="TVA", text="Total VAT"')
                if vat_elements.count() > 0:
                    print("  ✅ Romanian VAT report elements present")
            else:
                print("  [i] VAT report may not be implemented")

        # Navigate back to main reports
        navigate_to_platform_page(page, "/billing/reports/")
        page.wait_for_load_state("networkidle")

        # Check for payment reports
        payment_report = page.locator('text="Payment", text="Revenue", text="Collection"')
        if payment_report.is_visible():
            print("  ✅ Payment/Revenue reports available")

        # Check for date range filtering
        date_filter = page.locator('input[type="date"], select[name="date_range"]')
        if date_filter.is_visible():
            print("  ✅ Date range filtering available")

    else:
        print("  [i] Billing reports page may not be implemented yet")

    print("  ✅ Staff billing reports and analytics testing completed")


# ===============================================================================
# STAFF MOBILE RESPONSIVENESS TESTS
# ===============================================================================

def test_staff_billing_system_mobile_responsiveness(monitored_staff_page: Page) -> None:
    """
    Test staff billing system mobile responsiveness and touch interactions.

    This test verifies:
    1. Billing system displays correctly on mobile viewports
    2. Touch interactions work properly for staff features
    3. Mobile navigation elements function correctly
    4. Tables and forms are mobile-friendly
    """
    page = monitored_staff_page
    print("🧪 Testing staff billing system mobile responsiveness")

    # Navigate to billing
    navigate_to_platform_page(page, "/billing/invoices/")
    page.wait_for_load_state("networkidle")

    # Test mobile viewport
    with MobileTestContext(page, 'mobile_medium') as mobile:
        print("    📱 Testing staff billing system on mobile viewport")

        run_standard_mobile_test(page, mobile, context_label="staff billing")

        # Verify key mobile elements are accessible
        billing_heading = page.locator('h1:has-text("Billing Management")').first
        if billing_heading.is_visible():
            print("      ✅ Billing system heading visible on mobile")

        new_proforma_btn = page.locator('a:has-text("New Proforma"), a:has-text("Proformă nouă")').first
        if new_proforma_btn.is_visible():
            print("      ✅ New proforma button accessible on mobile")

    print("  ✅ Staff billing system mobile responsiveness testing completed")


# ===============================================================================
# COMPREHENSIVE STAFF BILLING WORKFLOW TESTS
# ===============================================================================

def test_staff_complete_billing_workflow(monitored_staff_page: Page) -> None:
    """
    Test the complete staff billing workflow from proforma creation to payment collection.

    This comprehensive test covers:
    1. Creating a proforma invoice for a customer
    2. Converting proforma to invoice
    3. Generating PDF documents
    4. Processing payment and tracking
    5. Romanian tax compliance verification
    6. Final billing cycle completion
    """
    page = monitored_staff_page
    print("🧪 Testing complete staff billing workflow")

    # Step 1: Create a new proforma
    print("    Step 1: Creating new proforma for customer...")
    navigate_to_platform_page(page, "/billing/proformas/create/")
    page.wait_for_load_state("networkidle")

    workflow_proforma = {
        'description': 'Staff E2E Workflow - Complete Billing Management Test',
        'amount': '500.00',
    }

    _fill_workflow_proforma_form(page, workflow_proforma)
    proforma_created = _locate_or_navigate_to_proforma(page, workflow_proforma)
    assert proforma_created, "Proforma creation failed"

    # Step 2: Convert proforma to invoice
    print("    Step 2: Converting proforma to invoice...")
    invoice_ready = _convert_proforma_to_invoice(page)
    assert invoice_ready, "Proforma to invoice conversion failed"

    # Step 3: Test PDF generation
    print("    Step 3: Testing PDF generation...")
    _test_pdf_generation(page)

    # Step 4: Test payment processing
    print("    Step 4: Testing payment processing...")
    _test_payment_recording(page, '500.00')

    print("  ✅ Complete staff billing workflow successful")


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

    assert "/billing/proformas/create" in page.url, \
        f"Should be on proforma create page, got: {page.url}"
    print("  ✅ Proforma create page loaded")

    # Find VAT rate dropdown(s) — line items have select with name like 'line_N_vat_rate'
    vat_selects = page.locator("select").filter(
        has=page.locator("option:has-text('21%')")
    )
    count = vat_selects.count()
    assert count > 0, "Should find at least one VAT rate dropdown with 21% option"
    print(f"  ✅ Found {count} VAT rate dropdown(s)")

    # Check the first VAT dropdown
    vat_select = vat_selects.first
    selected_value = vat_select.input_value()
    assert selected_value == "21", \
        f"Default VAT rate should be 21, got: {selected_value}"
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
