"""
Signup and Order E2E Tests for PRAHO Platform

This module comprehensively tests the customer signup and order flows including:
- User registration with customer organization onboarding
- Form validation and Romanian business compliance
- Post-signup login and dashboard access
- Order viewing for customers
- Combined signup -> login -> order viewing flow
- Security boundary testing for new accounts
- Mobile responsiveness for signup flow

Uses shared utilities from tests.e2e.utils for consistency.
Based on real customer onboarding workflows for PragmaticHost.
"""

import html
import json
import re
import secrets
import string

import pytest
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Locator, Page, expect

# Import shared utilities
from tests.e2e.helpers import (
    BASE_URL,
    REGISTER_URL,
    ComprehensivePageMonitor,
    assert_responsive_results,
    ensure_fresh_session,
    login_user,
    run_responsive_breakpoints_test,
)
from tests.e2e.helpers.orders import add_product, bank_checkout
from tests.e2e.helpers.registration import (
    CUI,
    confirmation_link,
    delivered_to,
    fill_confirmation,
    fill_registration,
    mailbox,
    new_identity,
    open_confirmation,
    register_customer,
    submit_registration,
)

# ===============================================================================
# TEST DATA GENERATORS
# ===============================================================================


def generate_test_email() -> str:
    """Generate a unique test email address"""
    random_suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return f"e2e_signup_test_{random_suffix}@test.praho.local"


# ===============================================================================
# SIGNUP PAGE ACCESS AND DISPLAY TESTS
# ===============================================================================


def test_signup_page_loads_correctly(page: Page) -> None:
    """
    Test that the signup page loads correctly with all required elements.

    This test verifies:
    1. Signup page is accessible at the register URL
    2. Page title and heading are correct
    3. All form sections are visible (Personal, Business, Address, Privacy)
    4. Required form fields are present
    5. Submit button is visible and enabled
    """
    print("Testing signup page loads correctly")

    with ComprehensivePageMonitor(
        page,
        "signup page load",
        check_console=True,  # console verified clean under current CSP (favicon.svg 404 fixed)
        check_network=True,
        check_html=True,
        check_css=True,
        check_accessibility=False,
    ):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Verify we're on the signup page
        assert REGISTER_URL in page.url, "Should be on signup page"

        # Verify page title
        title = page.title()
        assert "Create Account" in title or "PragmaticHost" in title, (
            f"Page title should contain 'Create Account', got: {title}"
        )

        # Verify main heading
        heading = page.locator("h1")
        expect(heading).to_have_text("Create your PRAHO account")
        print("  Signup page heading is correct")

        # Verify all form sections are present
        sections = [
            ("Personal Information", "Personal info section"),
            ("Business Information", "Business info section"),
            ("Address Information", "Address info section"),
            ("Privacy & Consent", "Privacy section"),
        ]

        for section_title, description in sections:
            section = page.locator(f'h3:has-text("{section_title}")')
            assert section.count() > 0, f"{description} should be visible"
            print(f"    {description} found")

        # Verify required form fields are present
        required_fields = [
            ('input[name="first_name"]', "First name field"),
            ('input[name="last_name"]', "Last name field"),
            ('input[name="email"]', "Email field"),
            ('select[name="customer_type"]', "Customer type dropdown"),
            ('input[name="company_name"]', "Company name field"),
            ('input[name="address_line1"]', "Address field"),
            ('input[name="city"]', "City field"),
            ('input[name="county"]', "County field"),
            ('input[name="postal_code"]', "Postal code field"),
            ('input[name="vat_number"]', "VAT number field"),
            ('input[name="cui"]', "CUI field"),
            ('input[name="trade_registry_number"]', "Trade registry number field"),
            ('input[name="terms_accepted"]', "Terms of Service checkbox"),
        ]

        for selector, field_name in required_fields:
            field = page.locator(selector)
            assert field.count() > 0, f"{field_name} should be present"
        print("    All required form fields are present")

        # Registration asks for no password: it is chosen on the emailed confirmation page.
        expect(page.locator('input[type="password"]')).to_have_count(0)
        # Nor a CNP: nothing needs one at registration.
        expect(page.locator('input[name="cnp"]')).to_have_count(0)

        # Verify submit button is present and enabled
        submit_button = page.locator('button:has-text("Create Account")')
        assert submit_button.is_visible(), "Submit button should be visible"
        assert submit_button.is_enabled(), "Submit button should be enabled"
        print("    Submit button is present and enabled")

        # Verify login link is present for existing users
        login_link = page.locator('a[href*="login"]:has-text("Sign in")')
        assert login_link.is_visible(), "Login link should be visible for existing users"
        print("    Login link for existing users is present")

        print("  Signup page loads correctly with all elements")


def test_signup_page_has_romanian_business_context(page: Page) -> None:
    """
    Test that the signup page shows Romanian business context and compliance elements.

    This test verifies:
    1. VAT number field shows Romanian format hint (RO12345678)
    2. Phone number shows Romanian format hint (+40.XX.XXX.XXXX)
    3. Customer type dropdown includes Romanian business types (SRL, PFA, II, etc.)
    4. GDPR consent is required
    """
    print("Testing signup page Romanian business context")

    with ComprehensivePageMonitor(
        page,
        "signup Romanian context",
        check_console=True,  # console verified clean under current CSP (favicon.svg 404 fixed)
        check_network=True,
        check_html=False,  # May have minor HTML issues
        check_css=True,
        check_accessibility=False,
    ):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        # Check VAT number field has Romanian format placeholder
        vat_field = page.locator('input[name="vat_number"]')
        if vat_field.is_visible():
            vat_placeholder = vat_field.get_attribute("placeholder") or ""
            assert "RO" in vat_placeholder or "12345678" in vat_placeholder, "VAT field should show Romanian format"
            print("    VAT field shows Romanian format hint")

        # Check phone field has Romanian format
        phone_field = page.locator('input[name="phone"]')
        if phone_field.is_visible():
            phone_placeholder = phone_field.get_attribute("placeholder") or ""
            assert "+40" in phone_placeholder, "Phone field should show Romanian format"
            print("    Phone field shows Romanian format hint")

        # Check customer type dropdown has Romanian business types
        customer_type_select = page.locator('select[name="customer_type"]')
        assert customer_type_select.is_visible(), "Customer type dropdown should be visible"

        # Get all options
        options = customer_type_select.locator("option").all()
        option_values = [opt.get_attribute("value") for opt in options]

        # Verify Romanian business types are available
        expected_types = ["srl", "pfa"]  # At minimum SRL and PFA
        for expected in expected_types:
            assert expected in option_values, f"Customer type should include {expected}"
        print(f"    Customer type includes Romanian business types: {option_values}")

        # The privacy notice replaces a consent checkbox: nobody is asked to tick one
        assert page.locator('input[name="data_processing_consent"]').count() == 0, "No consent checkbox"
        assert page.get_by_text("By creating an account you acknowledge the").is_visible()
        print("    Privacy notice is shown")

        print("  Romanian business context elements are correct")


# ===============================================================================
# SIGNUP FORM VALIDATION TESTS
# ===============================================================================


def test_signup_form_validation_required_fields(page: Page) -> None:
    page.goto(f"{BASE_URL}{REGISTER_URL}")
    page.get_by_role("button", name="Create Account", exact=True).click()
    expect(page).to_have_url(f"{BASE_URL}{REGISTER_URL}")
    assert page.locator('input[name="first_name"]').evaluate("el => el.validity.valueMissing")
    for field in ("email", "company_name", "address_line1", "terms_accepted"):
        expect(page.locator(f'input[name="{field}"]')).to_have_attribute("required", "")
    expect(page.locator('input[type="password"]')).to_have_count(0)


def test_signup_requires_a_vat_number_or_cui_for_a_romanian_company(page: Page) -> None:
    identity = new_identity()
    fill_registration(page, identity.email, identity.company)
    page.locator('input[name="cui"]').fill("")
    page.get_by_role("button", name="Create Account", exact=True).click()
    expect(page).to_have_url(f"{BASE_URL}{REGISTER_URL}")
    expect(page.locator("body")).to_contain_text("Enter the company's VAT number or CUI.")


def test_signup_form_email_validation(page: Page) -> None:
    """
    Test that the signup form validates email format properly.

    This test verifies:
    1. Invalid email formats are rejected
    2. Valid email formats are accepted
    """
    print("Testing signup form email validation")

    with ComprehensivePageMonitor(
        page,
        "signup email validation",
        check_console=True,  # console verified clean under current CSP (favicon.svg 404 fixed)
        check_network=True,
        check_html=False,
        check_css=True,
        check_accessibility=False,
    ):
        # Navigate to signup page
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        email_field = page.locator('input[name="email"]')

        # Test invalid email format
        # NOTE: "missing@domain" is valid per RFC 5321 (TLD-only domains accepted by browsers)
        invalid_emails = ["notanemail", "@nodomain.com"]

        for invalid_email in invalid_emails:
            email_field.fill(invalid_email)

            # Check HTML5 validation
            is_invalid = email_field.evaluate("el => !el.validity.valid")
            assert is_invalid, f"Invalid email '{invalid_email}' should be rejected by validation"
            print(f"    Invalid email '{invalid_email}' correctly rejected")

        # Test valid email format
        valid_email = generate_test_email()
        email_field.fill(valid_email)
        is_valid = email_field.evaluate("el => el.validity.valid")
        assert is_valid, f"Valid email '{valid_email}' should be accepted"
        print("    Valid email format accepted")

        print("  Email validation works correctly")


def test_signup_form_password_validation(page: Page, run_queued_tasks) -> None:
    """The password is chosen on the confirmation page, which refuses a mismatched confirmation."""
    identity = new_identity()
    before = mailbox()
    submit_registration(page, identity.email, identity.company)
    open_confirmation(page, confirmation_link(identity.email, before, run_queued_tasks), identity.company)
    fill_confirmation(page, identity.password, confirm_password="A-different-password123!")
    expect(page).to_have_url(f"{BASE_URL}/register/confirm/")
    expect(page.locator("body")).to_contain_text(re.compile("password.*match", re.I))


# ===============================================================================
# SUCCESSFUL SIGNUP FLOW TESTS
# ===============================================================================


def test_signup_form_successful_submission(page: Page) -> None:
    """Submitting asks the visitor to check their email; nothing is sent until a worker runs."""
    identity = new_identity()
    before = mailbox()
    submit_registration(page, identity.email, identity.company)
    assert not delivered_to(identity.email, before), "The request queues the mail; only a worker sends it"
    page.goto(f"{BASE_URL}/dashboard/")
    expect(page).to_have_url(re.compile("/login/"))


def test_signup_then_login_flow(page: Page, run_queued_tasks) -> None:
    """A confirmed registration signs in to its own company, with the CUI it registered."""
    identity = register_customer(page, run_queued_tasks)
    page.goto(f"{BASE_URL}/company/")
    expect(page.locator("#main-content")).to_contain_text(identity.company)
    page.goto(f"{BASE_URL}/company/tax/")
    expect(page.locator('[name="cui"]')).to_have_value(CUI)


# ===============================================================================
# ORDER VIEWING TESTS (Customer Perspective)
# ===============================================================================


def test_customer_can_view_product_catalog(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/order/")
    expect(page.locator("#cart-form-e2e-hosting")).to_be_visible()
    expect(page.locator('a[href="/order/products/e2e-hosting/"]').first).to_be_visible()


@pytest.mark.expect_server_errors("API request failed: Order not found")
def test_customer_order_confirmation_is_private(account_page, e2e_baseline) -> None:

    page, _ = account_page
    add_product(page)
    confirmation = bank_checkout(page)
    order_number = re.search(r"ORD-\d+", page.locator("#main-content").inner_text()).group()
    ensure_fresh_session(page)
    assert login_user(page, e2e_baseline["customers"][1]["email"], "admin123")
    response = page.goto(confirmation)
    assert response.status < 500
    expect(page.locator("#main-content")).not_to_contain_text(order_number)
    expect(page.get_by_role("heading", name="Awaiting your bank transfer")).to_have_count(0)
    assert page.url != confirmation or response.status in (403, 404)


# ===============================================================================
# COMBINED SIGNUP + ORDER FLOW TESTS
# ===============================================================================


def test_complete_new_customer_journey(page: Page, run_queued_tasks) -> None:
    """Public registration supplies enough billing data to submit a real bank order."""
    register_customer(page, run_queued_tasks)
    add_product(page)
    bank_checkout(page)


# ===============================================================================
# MOBILE RESPONSIVENESS TESTS
# ===============================================================================


def test_signup_page_mobile_responsiveness(page: Page) -> None:
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{BASE_URL}{REGISTER_URL}")
    for field in ("first_name", "email", "company_name"):
        expect(page.locator(f'input[name="{field}"]')).to_be_visible()
    expect(page.get_by_role("button", name="Create Account", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")


def test_signup_across_responsive_breakpoints(page: Page) -> None:
    """
    Test signup form across all responsive breakpoints.

    This test validates that the signup form works on:
    - Desktop viewports (baseline)
    - Tablet viewports
    - Mobile viewports
    """
    print("Testing signup across responsive breakpoints")

    with ComprehensivePageMonitor(
        page,
        "signup responsive breakpoints",
        check_console=True,  # console verified clean under current CSP (favicon.svg 404 fixed)
        check_network=True,
        check_html=False,
        check_css=True,
        check_accessibility=False,
    ):

        def test_signup_form_visibility(test_page: Page, context: str = "") -> bool:
            """Test that signup form is visible and functional"""
            try:
                test_page.goto(f"{BASE_URL}{REGISTER_URL}")
                test_page.wait_for_load_state("networkidle")

                # Check key form elements
                email_field = test_page.locator('input[name="email"]')
                submit_button = test_page.locator('button:has-text("Create Account")')

                email_visible = email_field.is_visible()
                submit_visible = submit_button.is_visible()

                if email_visible and submit_visible:
                    print(f"      Signup form visible in {context}")
                    return True
                else:
                    print(f"      Signup form issues in {context}")
                    return False

            except (TimeoutError, PlaywrightError) as e:
                print(f"      Error in {context}: {str(e)[:50]}")
                return False

        # Test across breakpoints
        results = run_responsive_breakpoints_test(page, test_signup_form_visibility)

        assert_responsive_results(results, "Signup form")

        print("  Signup responsive breakpoints test completed")


# ===============================================================================
# SECURITY BOUNDARY TESTS
# ===============================================================================


def test_duplicate_registration_preserves_existing_account(page: Page, e2e_baseline) -> None:
    """Registering an address that has an account says "check your email" like any other (#662),
    and changes nothing about that account."""
    customer = e2e_baseline["customers"][0]
    attempted = new_identity().company
    submit_registration(page, customer["email"], attempted)
    page.goto(f"{BASE_URL}/dashboard/")
    expect(page).to_have_url(re.compile("/login/"))
    assert login_user(page, customer["email"], "test123")
    page.goto(f"{BASE_URL}/company/")
    expect(page.locator("#main-content")).to_contain_text(customer["name"])
    expect(page.locator("#main-content")).not_to_contain_text(attempted)


# ===============================================================================
# EDGE CASE TESTS
# ===============================================================================


def test_signup_with_special_characters_in_company_name(page: Page, run_queued_tasks) -> None:
    """Romanian diacritics survive registration, the confirmation page, API transport and display."""
    identity = register_customer(page, run_queued_tasks, company_suffix="Știință și Tehnică")
    page.goto(f"{BASE_URL}/company/")
    expect(page.locator("#main-content")).to_contain_text(identity.company)


# ===============================================================================
# ORDER FLOW COVERAGE TESTS
# ===============================================================================


def test_customer_product_detail_page(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/order/products/e2e-hosting/")
    expect(page.get_by_role("heading", name="E2E Hosting", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Add to Cart", exact=True)).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text("100,00 RON")


def test_customer_cart_management(monitored_customer_page: Page) -> None:

    page = monitored_customer_page
    add_product(page)
    page.goto(f"{BASE_URL}/order/cart/")
    expect(page.locator("#main-content")).to_contain_text("E2E Hosting")
    expect(page.locator("#cart-totals")).to_contain_text("121,00")
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator('#cart-items button[aria-label="Remove from cart"]').click()
    expect(page.locator("#main-content")).to_contain_text("Your cart is empty")
    page.reload()
    expect(page.locator("#main-content")).to_contain_text("Your cart is empty")


def _add_product_to_cart(page: Page) -> bool:

    return add_product(page)


def test_customer_checkout_page(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    add_product(page)
    page.goto(f"{BASE_URL}/order/checkout/")
    expect(page).to_have_url(f"{BASE_URL}/order/checkout/")
    expect(page.locator("#checkout-submit")).to_be_visible()
    expect(page.locator('[name="agree_terms"]')).not_to_be_checked()
    expect(page.locator('[name="payment_method"]')).to_have_count(2)
    expect(page.locator("#main-content")).to_contain_text("E2E Hosting")
    expect(page.locator("#main-content")).to_contain_text("121,00")


def test_customer_order_creation_flow(account_page) -> None:

    page, _ = account_page
    add_product(page)
    bank_checkout(page)


def test_customer_mini_cart_partial(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    add_product(page)
    response = page.request.get(f"{BASE_URL}/order/partials/mini-cart/", headers={"HX-Request": "true"})
    assert response.status == 200
    assert "E2E Hosting" in response.text()
    # Read the remove button's payload the way HTMX does: decode the attribute, then parse the JSON
    payloads = re.findall(r"hx-vals='([^']*)'", response.text())
    assert [json.loads(html.unescape(payload)) for payload in payloads] == [
        {"product_slug": "e2e-hosting", "billing_period": "monthly"}
    ]
    assert "/order/cart/" in response.text()


def test_customer_cart_calculate_totals(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    add_product(page)
    token = page.locator('[name="csrfmiddlewaretoken"]').first.input_value()
    response = page.request.post(
        f"{BASE_URL}/order/cart/calculate/", headers={"HX-Request": "true", "X-CSRFToken": token}
    )
    assert response.status == 200
    for expected in ("100,00", "VAT (21%)", "21,00", "121,00"):
        assert expected in response.text()


# ===============================================================================
# QA FIX REGRESSION TESTS
# ===============================================================================


def test_registration_form_has_terms_accepted_checkbox(page: Page) -> None:
    """C2: Registration form has a terms_accepted checkbox (required, not missing from form)."""
    print("🧪 Testing registration form has terms_accepted checkbox")

    with ComprehensivePageMonitor(
        page,
        "registration terms checkbox",
        check_console=True,  # console verified clean under current CSP (favicon.svg 404 fixed)
        check_network=True,
        check_html=True,
        check_css=True,
        check_accessibility=False,
        allow_accessibility_skip=True,
        check_performance=False,
    ):
        page.goto(f"{BASE_URL}{REGISTER_URL}")
        page.wait_for_load_state("networkidle")

        assert REGISTER_URL in page.url, f"Should be on register page, got: {page.url}"
        print("    ✅ Registration page loaded")

        # The terms_accepted checkbox must be present in the form
        terms_checkbox: Locator = page.locator(
            'input[name="terms_accepted"], input[name="terms"], input[type="checkbox"][name*="terms"]'
        )
        assert terms_checkbox.count() > 0, (
            "Registration form must have a 'terms_accepted' checkbox — "
            "if missing the form will submit without consent and fail server-side"
        )
        expect(terms_checkbox.first).to_be_visible()
        print("    ✅ terms_accepted checkbox is present and visible")

        # It should be unchecked by default (user must actively accept)
        is_checked: bool = terms_checkbox.first.is_checked()
        assert not is_checked, "terms_accepted checkbox should default to unchecked"
        print("    ✅ Checkbox defaults to unchecked (requires explicit acceptance)")

        # The label should reference terms/privacy
        page_text: str = page.text_content("body") or ""
        has_terms_text: bool = any(
            keyword in page_text.lower() for keyword in ["terms", "privacy", "conditions", "termeni", "politica"]
        )
        assert has_terms_text, "Page should mention terms/conditions/privacy near the checkbox"
        print("    ✅ Terms/conditions text present on registration page")

    print("  ✅ Registration terms_accepted checkbox test completed")


def test_cart_order_summary_loads_without_error(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    add_product(page)
    page.goto(f"{BASE_URL}/order/cart/")
    expect(page.locator("#cart-totals")).to_contain_text("121,00")
    expect(page.locator("#cart-totals")).to_contain_text("VAT (21%)")
    expect(page.get_by_role("link", name="Continue to checkout", exact=False)).to_be_visible()


def test_cart_quantity_change_recalculates_totals_no_400(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _add_product_to_cart(page)
    page.goto(f"{BASE_URL}/order/cart/")
    expect(page.locator("#cart-totals")).to_contain_text("121,00")
    page.locator('select[name="quantity"]').select_option("2")
    expect(page.locator("#cart-totals")).to_contain_text("242,00")
    page.reload()
    expect(page.locator('select[name="quantity"]')).to_have_value("2")
    expect(page.locator("#cart-totals")).to_contain_text("242,00")


def test_cart_remove_item_updates_summary_cleanly(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _add_product_to_cart(page)
    page.goto(f"{BASE_URL}/order/cart/")
    page.on("dialog", lambda dialog: dialog.accept())
    page.locator('#cart-items button[aria-label*="Remove"]').click()
    expect(page.locator("#cart-items")).to_contain_text("Your cart is empty")
    expect(page.locator('#cart-items select[name="quantity"]')).to_have_count(0)
    page.reload()
    expect(page.locator("#cart-count")).to_have_count(0)


def test_checkout_preflight_slug_only_path_no_uuid_error(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    add_product(page)
    page.goto(f"{BASE_URL}/order/checkout/")
    expect(page).to_have_url(f"{BASE_URL}/order/checkout/")
    expect(page.locator("#checkout-submit")).to_be_enabled()
    expect(page.locator("#main-content")).to_contain_text("E2E Hosting")
    expect(page.locator("#main-content")).to_contain_text("121,00")
