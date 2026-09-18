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

import re
import secrets
import string
from uuid import uuid4

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

# ===============================================================================
# TEST DATA GENERATORS
# ===============================================================================


def generate_test_email() -> str:
    """Generate a unique test email address"""
    random_suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return f"e2e_signup_test_{random_suffix}@test.praho.local"


def generate_test_phone() -> str:
    """Generate a random Romanian phone number"""
    # Romanian mobile format: +40.7XX.XXX.XXX
    return f"+40.7{secrets.randbelow(10)}{secrets.randbelow(10)}.{secrets.randbelow(1000):03d}.{secrets.randbelow(1000):03d}"


def generate_test_company_name() -> str:
    """Generate a unique test company name"""
    prefixes = ["Test", "E2E", "Auto", "QA"]
    suffixes = ["Solutions", "Tech", "Services", "Digital"]
    random_num = secrets.randbelow(9999) + 1
    return f"{secrets.choice(prefixes)} {secrets.choice(suffixes)} {random_num} SRL"


def generate_test_password() -> str:
    """Generate a secure test password meeting requirements"""
    # Password requirements: minimum 12 characters
    return f"TestPass123!{secrets.randbelow(9999):04d}"


# ===============================================================================
# SIGNUP PAGE ACCESS AND DISPLAY TESTS
# ===============================================================================


def test_signup_page_loads_correctly(page: Page) -> None:
    """
    Test that the signup page loads correctly with all required elements.

    This test verifies:
    1. Signup page is accessible at the register URL
    2. Page title and heading are correct
    3. All form sections are visible (Personal, Business, Address, Security, Privacy)
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
        expect(heading).to_contain_text("Create Your PragmaticHost Account")
        print("  Signup page heading is correct")

        # Verify all form sections are present
        sections = [
            ("Personal Information", "Personal info section"),
            ("Business Information", "Business info section"),
            ("Address Information", "Address info section"),
            ("Account Security", "Security section"),
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
            ('input[name="password1"]', "Password field"),
            ('input[name="password2"]', "Confirm password field"),
            ('input[name="data_processing_consent"]', "GDPR consent checkbox"),
        ]

        for selector, field_name in required_fields:
            field = page.locator(selector)
            assert field.count() > 0, f"{field_name} should be present"
        print("    All required form fields are present")

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

        # Verify GDPR consent checkbox is present and required
        gdpr_checkbox = page.locator('input[name="data_processing_consent"]')
        assert gdpr_checkbox.is_visible(), "GDPR consent checkbox should be visible"
        print("    GDPR consent checkbox is present")

        print("  Romanian business context elements are correct")


# ===============================================================================
# SIGNUP FORM VALIDATION TESTS
# ===============================================================================


def test_signup_form_validation_required_fields(page: Page) -> None:
    page.goto(f"{BASE_URL}{REGISTER_URL}")
    page.get_by_role("button", name="Create Account", exact=True).click()
    expect(page).to_have_url(f"{BASE_URL}{REGISTER_URL}")
    assert page.locator('input[name="first_name"]').evaluate("el => el.validity.valueMissing")
    for field in ("email", "password1", "password2", "data_processing_consent", "terms_accepted"):
        expect(page.locator(f'input[name="{field}"]')).to_have_attribute("required", "")


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


def test_signup_form_password_validation(page: Page) -> None:
    _fill_registration(page, generate_test_email(), "Mismatched Passwords SRL")
    page.locator('[name="password2"]').fill("A-different-password123!")
    page.get_by_role("button", name="Create Account", exact=True).click()
    expect(page).to_have_url(f"{BASE_URL}{REGISTER_URL}")
    expect(page.locator("body")).to_contain_text(re.compile("password.*match", re.I))


# ===============================================================================
# SUCCESSFUL SIGNUP FLOW TESTS
# ===============================================================================


def test_signup_form_successful_submission(page: Page) -> None:
    """Registration creates a login-capable account with its own persisted company."""
    account = _register_customer(page)
    ensure_fresh_session(page)
    assert login_user(page, account["email"], account["password"])
    page.goto(f"{BASE_URL}/company/")
    expect(page.locator("#main-content")).to_contain_text(account["company"])


def test_signup_then_login_flow(page: Page) -> None:
    """Registration creates a login-capable account with its own persisted company."""
    account = _register_customer(page)
    ensure_fresh_session(page)
    assert login_user(page, account["email"], account["password"])
    page.goto(f"{BASE_URL}/company/")
    expect(page.locator("#main-content")).to_contain_text(account["company"])


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


def _journey_fill_registration_form(page: Page, test_email: str, test_password: str, test_company: str) -> None:
    """Step 2: Fill all fields in the customer registration form."""
    page.locator('input[name="first_name"]').fill("Journey")
    page.locator('input[name="last_name"]').fill("TestUser")
    page.locator('input[name="email"]').fill(test_email)
    page.locator('input[name="phone"]').fill(generate_test_phone())
    page.locator('select[name="customer_type"]').select_option("srl")
    page.locator('input[name="company_name"]').fill(test_company)
    page.locator('input[name="vat_number"]').fill("RO12345678")
    page.locator('input[name="address_line1"]').fill("Bulevardul Test Nr. 100")
    page.locator('input[name="city"]').fill("Bucuresti")
    page.locator('input[name="county"]').fill("Bucuresti")
    page.locator('input[name="postal_code"]').fill("010001")
    page.locator('input[name="password1"]').fill(test_password)
    page.locator('input[name="password2"]').fill(test_password)
    page.locator('input[name="data_processing_consent"]').check()
    page.locator('input[name="terms_accepted"]').check()

    marketing_checkbox = page.locator('input[name="marketing_consent"]')
    if marketing_checkbox.is_visible():
        marketing_checkbox.check()

    print("    Step 2: Registration form filled")


def test_complete_new_customer_journey(page: Page) -> None:
    """Public registration supplies enough billing data to submit a real bank order."""

    _register_customer(page)
    add_product(page)
    bank_checkout(page)


# ===============================================================================
# MOBILE RESPONSIVENESS TESTS
# ===============================================================================


def test_signup_page_mobile_responsiveness(page: Page) -> None:
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{BASE_URL}{REGISTER_URL}")
    for field in ("first_name", "email", "password1"):
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
    """Registration reports failure generically; it does not promise indistinguishable success."""
    customer = e2e_baseline["customers"][0]
    _fill_registration(page, customer["email"], "Attempted replacement company")
    page.get_by_role("button", name="Create Account", exact=True).click()
    expect(page).to_have_url(f"{BASE_URL}{REGISTER_URL}")
    expect(page.locator("body")).to_contain_text("Registration failed")
    page.goto(f"{BASE_URL}/dashboard/")
    expect(page).to_have_url(re.compile("/login/"))
    assert login_user(page, customer["email"], "test123")
    page.goto(f"{BASE_URL}/company/")
    expect(page.locator("#main-content")).to_contain_text(customer["name"])
    expect(page.locator("#main-content")).not_to_contain_text("Attempted replacement company")


# ===============================================================================
# EDGE CASE TESTS
# ===============================================================================


def test_signup_with_special_characters_in_company_name(page: Page) -> None:
    """Romanian diacritics survive registration, API transport and display."""
    _register_customer(page, company_suffix="Știință și Tehnică")


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
    assert '"product_slug": "e2e-hosting"' in response.text()
    assert '"billing_period": "monthly"' in response.text()
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


def _register_customer(page: Page, *, company_suffix: str = "") -> dict[str, str]:

    key = uuid4().hex[:12]
    account = {
        "email": f"signup-{key}@e2e.test",
        "password": "Registration-E2E123!",
        "company": f"E2E {key} {company_suffix} SRL",
    }
    ensure_fresh_session(page)
    page.goto(f"{BASE_URL}{REGISTER_URL}")
    for field, value in {
        "email": account["email"],
        "first_name": "Elena",
        "last_name": "Pop",
        "phone": "+40722123456",
        "company_name": account["company"],
        "address_line1": "Str. Victoriei nr. 10",
        "city": "București",
        "county": "București",
        "postal_code": "010061",
        "password1": account["password"],
        "password2": account["password"],
    }.items():
        page.locator(f'input[name="{field}"]').fill(value)
    page.locator('select[name="customer_type"]').select_option("srl")
    page.locator('input[name="data_processing_consent"]').check()
    page.locator('input[name="terms_accepted"]').check()
    page.get_by_role("button", name="Create Account", exact=True).click()
    expect(page).to_have_url(f"{BASE_URL}/login/")
    assert login_user(page, account["email"], account["password"])
    page.goto(f"{BASE_URL}/company/")
    expect(page.locator("#main-content")).to_contain_text(account["company"])
    return account


def _fill_registration(page: Page, email: str, company: str) -> None:
    ensure_fresh_session(page)
    page.goto(f"{BASE_URL}{REGISTER_URL}")
    for field, value in {
        "first_name": "Test",
        "last_name": "User",
        "email": email,
        "company_name": company,
        "address_line1": "Str. Victoriei nr. 10",
        "city": "București",
        "county": "București",
        "postal_code": "010061",
        "password1": "Registration-E2E123!",
        "password2": "Registration-E2E123!",
    }.items():
        page.locator(f'input[name="{field}"]').fill(value)
    page.locator('[name="customer_type"]').select_option("srl")
    page.locator('[name="data_processing_consent"]').check()
    page.locator('[name="terms_accepted"]').check()
