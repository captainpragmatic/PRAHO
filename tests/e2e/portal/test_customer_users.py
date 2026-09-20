"""
Customer User Management E2E Tests for PRAHO Platform

This module comprehensively tests the customer-facing user functionality including:
- User authentication and session management
- Profile management and editing
- Password change functionality
- Two-factor authentication setup and management (TOTP/WebAuthn)
- Account security settings and features
- Security boundary testing - ensuring customers cannot access staff-only URLs
- Mobile responsiveness for customer profile management
- Customer account security and privacy

Uses shared utilities from tests.e2e.utils for consistency.
Based on real customer workflows for user account management.
"""

import re

import pyotp
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Locator, Page, expect

# Import shared utilities
from tests.e2e.helpers import (
    BASE_URL,
    PLATFORM_BASE_URL,
    assert_responsive_results,
    ensure_fresh_session,
    login_user,
    navigate_to_dashboard,
    require_authentication,
    run_responsive_breakpoints_test,
)

# ===============================================================================
# CUSTOMER AUTHENTICATION AND PROFILE ACCESS TESTS
# ===============================================================================


def test_customer_login_and_profile_access(monitored_customer_page: Page) -> None:
    """
    Test customer login and basic profile access using dynamic test users.

    This test verifies:
    1. Fresh customer user can login successfully
    2. Customer can access their profile page
    3. Customer profile displays correct information
    4. Authentication is maintained across navigation
    5. Clean test isolation with automatic cleanup
    """
    print("🧪 Testing customer login and profile access")

    page = monitored_customer_page

    require_authentication(page)

    # Navigate to dashboard first
    assert navigate_to_dashboard(page)
    expect(page).to_have_url(re.compile(r"/dashboard/"))

    # Navigate to user profile
    page.goto(f"{BASE_URL}/profile/")
    page.wait_for_load_state("networkidle")

    # Verify we're on the profile page
    expect(page).to_have_url(re.compile(r"/profile/"))

    # Verify profile page title and content
    page_title = page.title()
    title_ok = any(word in page_title.lower() for word in ["profile", "profil", "account", "settings"])
    if not title_ok:
        print(f"  [i] Profile page title: '{page_title}' (may vary)")

    # Check for profile page elements (fields may not be wrapped in a <form> tag)
    # Complex OR condition: save_button or profile_fields present
    save_button = page.locator('button:has-text("Save"), button:has-text("Update"), button[type="submit"]')
    profile_fields = page.locator('input[name="first_name"], input[name="last_name"]')
    assert save_button.count() > 0 or profile_fields.count() > 0, (
        "Profile page should have editable fields or save button"
    )

    # Check for basic profile fields
    first_name_field = page.locator('input[name="first_name"]')
    last_name_field = page.locator('input[name="last_name"]')
    email_field = page.locator('input[name="email"], input[type="email"]')

    expect(first_name_field).to_be_visible()
    print("  ✅ First name field available")
    expect(last_name_field).to_be_visible()
    print("  ✅ Last name field available")
    expect(email_field).to_be_visible()
    print("  ✅ Email field visible in profile")

    # Check for 2FA management section
    mfa_section = page.locator('div:has-text("Two-Factor"), div:has-text("2FA"), a[href*="2fa"]')
    if mfa_section.count() > 0:
        print("  ✅ 2FA management section available")
    else:
        print("  [i] 2FA management section not found in profile")


def test_customer_profile_using_convenience_helper(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/profile/")
    expect(page.locator('input[name="email"]')).to_have_value(e2e_baseline["customers"][0]["email"])
    expect(page.locator('input[name="first_name"]')).to_be_visible()
    expect(page.locator('input[name="last_name"]')).to_be_visible()
    expect(page.get_by_role("button", name=re.compile("Save|Update"))).to_be_visible()
    expect(page.locator('a[href="/change-password/"]')).to_be_visible()


def test_customer_profile_editing(account_page) -> None:
    page, _account = account_page
    page.goto(f"{BASE_URL}/profile/")
    for field, value in {"first_name": "CustomerTest", "last_name": "UserTest", "phone": "+40711223344"}.items():
        page.locator(f'input[name="{field}"]').fill(value)
    with page.expect_response(
        lambda response: response.url == f"{BASE_URL}/profile/" and response.request.method == "POST"
    ) as saved:
        page.get_by_role("button", name=re.compile("Save|Update")).click()
    assert saved.value.status == 302
    expect(page.locator("body")).to_contain_text("Profile updated successfully!")
    page.reload()
    for field, value in {"first_name": "CustomerTest", "last_name": "UserTest", "phone": "+40711223344"}.items():
        expect(page.locator(f'input[name="{field}"]')).to_have_value(value)


# ===============================================================================
# CUSTOMER PASSWORD CHANGE TESTS
# ===============================================================================


def test_customer_password_change_workflow(account_page) -> None:
    """Password change invalidates the old password and permits a new session."""
    page, account = account_page
    page.goto(f"{BASE_URL}/change-password/")
    page.locator('input[name="current_password"]').fill(account["password"])
    page.locator('input[name="new_password"]').fill("Changed-E2E-pass123!")
    page.locator('input[name="confirm_password"]').fill("Changed-E2E-pass123!")
    page.get_by_role("button", name="Change Password", exact=True).click()
    expect(page.locator("body")).to_contain_text("Password changed successfully!")
    ensure_fresh_session(page)
    assert not login_user(page, account["email"], account["password"])
    assert login_user(page, account["email"], "Changed-E2E-pass123!")
    page.goto(f"{BASE_URL}/profile/")
    expect(page.locator('input[name="email"]')).to_have_value(account["email"])


# ===============================================================================
# CUSTOMER TWO-FACTOR AUTHENTICATION TESTS
# ===============================================================================


def test_customer_2fa_setup_access_and_flow(account_page) -> None:
    """An enrolled account needs a second factor; disabling requires step-up credentials."""
    page, account = account_page
    codes = _enable_totp(page)
    ensure_fresh_session(page)
    assert not login_user(page, account["email"], account["password"])
    page.goto(f"{BASE_URL}/login/")
    page.locator('input[name="email"]').fill(account["email"])
    page.locator('input[name="password"]').fill(account["password"])
    page.locator('input[name="mfa_token"]').fill(codes[0])
    page.locator('form button[type="submit"]').click()
    expect(page).to_have_url(re.compile(r"/dashboard/$"))
    page.goto(f"{BASE_URL}/mfa/disable/")
    page.locator('input[name="password"]').fill(account["password"])
    page.locator('input[name="token"]').fill(codes[1])
    page.get_by_role("button", name="Disable MFA", exact=True).click()
    expect(page).to_have_url(re.compile(r"/mfa/$"))
    page.reload()
    expect(page.locator('a[href="/mfa/setup/totp/"]')).to_be_visible()
    ensure_fresh_session(page)
    assert login_user(page, account["email"], account["password"])


# ===============================================================================
# CUSTOMER SECURITY BOUNDARY TESTS
# ===============================================================================


def test_customer_staff_access_restrictions(monitored_customer_page: Page, e2e_baseline) -> None:

    page = monitored_customer_page
    for path in ("/auth/users/", f"/auth/users/{e2e_baseline['customers'][1]['user_id']}/"):
        response = page.request.get(PLATFORM_BASE_URL + path, max_redirects=0)
        assert response.status == 302
        response = page.request.get(PLATFORM_BASE_URL + path)
        assert response.status == 200
        assert "/auth/login/" in response.url
        assert e2e_baseline["customers"][1]["email"] not in response.text()
    page.goto(f"{BASE_URL}/profile/")
    expect(page.locator('input[name="email"]')).to_have_value(e2e_baseline["customers"][0]["email"])


def test_customer_cannot_edit_other_users(account_page, e2e_baseline) -> None:
    page, account = account_page
    other = e2e_baseline["customers"][1]
    page.goto(f"{BASE_URL}/profile/")
    page.locator('[name="first_name"]').fill("ChangedOnlyOwn")
    page.locator('form:has([name="first_name"])').evaluate(
        """(form, identity) => {
        for (const [name, value] of Object.entries(identity)) {
            const input = document.createElement('input');
            input.type = 'hidden'; input.name = name; input.value = value; form.append(input);
        }
    }""",
        {"user_id": str(other["user_id"]), "customer_id": str(other["id"])},
    )
    page.get_by_role("button", name=re.compile("Save|Update")).click()
    expect(page.locator("body")).to_contain_text("Profile updated successfully")
    page.reload()
    expect(page.locator('input[name="first_name"]')).to_have_value("ChangedOnlyOwn")
    expect(page.locator('input[name="email"]')).to_have_value(account["email"])
    ensure_fresh_session(page)
    assert login_user(page, other["email"], "admin123")
    page.goto(f"{BASE_URL}/profile/")
    expect(page.locator('input[name="first_name"]')).to_have_value("E2E")
    expect(page.locator('input[name="email"]')).to_have_value(other["email"])


# ===============================================================================
# CUSTOMER MOBILE RESPONSIVENESS TESTS
# ===============================================================================


def test_customer_profile_mobile_responsiveness(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{BASE_URL}/profile/")
    expect(page.locator('input[name="first_name"]')).to_be_visible()
    expect(page.locator('input[name="last_name"]')).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


# ===============================================================================
# COMPREHENSIVE CUSTOMER WORKFLOW TESTS
# ===============================================================================


def test_customer_complete_account_management_workflow(account_page) -> None:
    """Profile edits persist across logout and a new authenticated session."""
    page, account = account_page
    page.goto(f"{BASE_URL}/profile/")
    page.locator('input[name="first_name"]').fill("Updated")
    page.locator('input[name="last_name"]').fill("Account")
    page.get_by_role("button", name=re.compile("Save|Update")).click()
    ensure_fresh_session(page)
    assert login_user(page, account["email"], account["password"])
    page.goto(f"{BASE_URL}/profile/")
    expect(page.locator('input[name="first_name"]')).to_have_value("Updated")
    expect(page.locator('input[name="last_name"]')).to_have_value("Account")
    page.goto(f"{BASE_URL}/company/")
    expect(page.locator("#main-content")).to_contain_text(account["name"])


def test_customer_account_responsive_breakpoints(monitored_customer_page: Page) -> None:
    """
    Test customer account management across all responsive breakpoints.

    This test validates that customer account functionality works on:
    - Desktop viewports (baseline)
    - Tablet viewports (landscape and portrait)
    - Mobile viewports (various sizes)
    """
    print("🧪 Testing customer account management across responsive breakpoints")

    page = monitored_customer_page

    def test_customer_account_functionality(test_page, context="general"):
        """Test core customer account functionality across viewports."""
        try:
            # Navigate to profile
            test_page.goto(f"{BASE_URL}/profile/")
            test_page.wait_for_load_state("networkidle")

            # Verify authentication maintained
            require_authentication(test_page)

            # Check core elements are present (fields may not be in a <form> wrapper)
            profile_fields = test_page.locator(
                'input[name="first_name"], input[name="last_name"], button:has-text("Save")'
            )

            elements_present = profile_fields.count() > 0

            if elements_present:
                print(f"      ✅ Customer account management functional in {context}")
                return True
            else:
                print(f"      ❌ Core account elements missing in {context}")
                return False

        except (TimeoutError, PlaywrightError) as e:
            print(f"      ❌ Account management test failed in {context}: {str(e)[:50]}")
            return False

    # Test across all breakpoints
    results = run_responsive_breakpoints_test(page, test_customer_account_functionality)

    # Verify all breakpoints pass
    assert_responsive_results(results, "Customer account management")

    print("  ✅ Customer account management validated across all responsive breakpoints")


# ===============================================================================
# CUSTOMER COMPANY PROFILE, PRIVACY, AND MFA TESTS
# ===============================================================================


def test_customer_company_profile_view(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/company/")
    expect(page.get_by_role("heading", name="Company Profile", exact=True)).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text(e2e_baseline["customers"][0]["name"])
    expect(page.locator("#main-content")).to_contain_text("RO14399847")
    expect(page.locator("#main-content")).to_contain_text("Str. Victoriei nr. 10")
    expect(page.get_by_role("link", name="Edit Company Profile")).to_be_visible()


def test_customer_company_profile_edit(account_page) -> None:
    page, account = account_page
    page.goto(f"{BASE_URL}/company/edit/")
    field = page.locator('input[name="company_name"]')
    expect(field).to_have_value(account["name"])
    field.fill(account["name"] + " Updated")
    page.get_by_role("button", name=re.compile("Save")).click()
    expect(page).to_have_url(f"{BASE_URL}/company/")
    page.reload()
    expect(page.locator("#main-content")).to_contain_text(account["name"] + " Updated")


def test_customer_privacy_dashboard(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/privacy/")
    expect(page.get_by_role("heading", name="Privacy Dashboard", exact=True)).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text("Data Processing")
    expect(page.locator("#main-content")).to_contain_text("Marketing")
    expect(page.locator('a[href="/data-export/"]')).to_be_visible()
    expect(page.locator('a[href*="consent-history"]')).to_be_visible()


def test_customer_data_export_request(account_page) -> None:
    """Persist a queued export request; email/worker delivery is a separate integration boundary."""
    page, account = account_page
    page.goto(f"{BASE_URL}/data-export/")
    expect(page.get_by_role("heading", name="Export My Data", exact=True)).to_be_visible()
    page.get_by_role("button", name="Request Data Export").click()
    expect(page.locator("body")).to_contain_text("Data export request submitted successfully")
    page.reload()
    expect(page.locator("#main-content")).to_contain_text("Export History")
    expect(page.locator("#main-content")).to_contain_text("Pending")
    expect(page.locator("#main-content")).to_contain_text(account["email"])


def test_customer_mfa_management_hub(account_page) -> None:
    page, _ = account_page
    page.goto(f"{BASE_URL}/mfa/")
    expect(page.get_by_role("heading", name="Two-Factor Authentication", exact=True)).to_be_visible()
    expect(page.locator('a[href="/mfa/setup/totp/"]')).to_be_visible()
    expect(page.locator('a[href="/mfa/backup-codes/"]')).to_have_count(0)


def test_customer_mfa_backup_codes(account_page) -> None:
    """Recovery codes are displayed once and regenerated only after reauthentication."""
    page, account = account_page
    page.goto(f"{BASE_URL}/mfa/backup-codes/")
    expect(page).to_have_url(re.compile(r"/mfa/$"))
    expect(page.locator("body")).to_contain_text("enable 2FA first")
    codes = _enable_totp(page)
    page.reload()
    expect(page.locator("code")).to_have_count(0)
    expect(page.locator("#main-content")).to_contain_text("cannot be displayed again")
    page.locator('input[name="password"]').fill(account["password"])
    page.locator('input[name="token"]').fill(codes[0])
    page.get_by_role("button", name="Generate New Backup Codes", exact=True).click()
    expect(page.locator("code")).to_have_count(8)
    assert not set(codes).intersection(page.locator("code").all_text_contents())


# ===============================================================================
# CUSTOMER COMPANY CREATE AND SWITCH CUSTOMER TESTS
# ===============================================================================


def test_customer_company_creation_form_available(monitored_customer_page: Page) -> None:
    """Current multi-company behavior allows another company; opening it changes no membership."""
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/company/create/")
    expect(page).to_have_url(f"{BASE_URL}/company/create/")
    expect(page.locator('input[name="company_name"]')).to_be_visible()
    expect(page.locator('input[name="company_name"]')).to_have_value("")


def test_customer_switch_customer_single_org(account_page, e2e_baseline) -> None:
    page, account = account_page
    page.goto(f"{BASE_URL}/profile/")
    token = page.locator('input[name="csrfmiddlewaretoken"]').first.input_value()
    for customer_id in (account["customer_id"], e2e_baseline["customers"][1]["id"]):
        response = page.request.post(
            f"{BASE_URL}/switch-customer/",
            form={
                "csrfmiddlewaretoken": token,
                "customer_id": str(customer_id),
            },
        )
        assert response.status == 200
        if customer_id == account["customer_id"]:
            assert "Switched to" in response.text()
        else:
            assert "don&#x27;t have access" in response.text() or "don't have access" in response.text()
        page.goto(f"{BASE_URL}/company/")
        expect(page.locator("#main-content")).to_contain_text(account["name"])
        expect(page.locator("#main-content")).not_to_contain_text(e2e_baseline["customers"][1]["name"])


# ===============================================================================
# PASSWORD RESET TESTS
# ===============================================================================


def test_customer_password_reset_form(page: Page) -> None:
    """
    Test the password reset form renders and accepts an email submission.

    Validates:
    - Password reset page loads at /password-reset/ (unauthenticated)
    - Form contains an email input field
    - Submitting an email shows a uniform success message (ADR-003 email enumeration prevention)
    """
    print("🧪 Testing customer password reset form")

    ensure_fresh_session(page)

    # Navigate to password reset page (no login needed)
    print("  🔑 Navigating to password reset page...")
    page.goto(f"{BASE_URL}/password-reset/")
    page.wait_for_load_state("networkidle")

    # Verify heading
    heading: Locator = page.locator("h2:has-text('Reset Your Password')")
    expect(heading).to_be_visible()
    print("    ✅ Password reset page heading visible")

    # Verify email input field is present
    email_input: Locator = page.locator("input[type='email'], input[name='email']")
    expect(email_input).to_be_visible()
    print("    ✅ Email input field present")

    # Verify submit button
    submit_btn: Locator = page.locator("button[type='submit']:has-text('Send Password Reset')")
    expect(submit_btn).to_be_visible()
    print("    ✅ Submit button present")

    # Verify back to login link
    back_link: Locator = page.locator("a[href*='login']:has-text('Back to login')")
    expect(back_link).to_be_visible()
    print("    ✅ Back to login link present")

    # Submit the form with a test email
    print("  📧 Submitting password reset form...")
    email_input.fill("test-reset@example.com")
    submit_btn.click()
    page.wait_for_load_state("networkidle")

    # Verify uniform success message (ADR-003: no email enumeration)
    success_message: Locator = page.locator("text=If an account with that email exists")
    expect(success_message).to_be_visible(timeout=5000)
    print("    ✅ Uniform success message displayed (email enumeration prevention)")

    print("  ✅ Customer password reset form test completed")


# ===============================================================================
# QA FIX REGRESSION TESTS
# ===============================================================================


def test_company_profile_shows_name_not_not_specified(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/profile/")
    expect(page.locator("#main-content")).to_contain_text(e2e_baseline["customers"][0]["name"])
    expect(page.locator("#main-content")).not_to_contain_text("No company profile yet")


def test_profile_shows_member_since_date(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/profile/")
    value = page.locator('dt:has-text("Member Since") + dd')
    expect(value).to_have_text(re.compile(r"\d{4}"))
    expect(value).not_to_have_text("N/A")


def _enable_totp(page: Page) -> list[str]:

    page.goto(f"{BASE_URL}/mfa/setup/totp/")
    secret = page.locator("#secret-key").text_content().strip()
    assert len(secret) >= 16
    assert page.locator('img[alt="MFA QR Code"]').evaluate("(img) => img.complete && img.naturalWidth > 0")
    page.locator('input[name="token"]').fill(pyotp.TOTP(secret).now())
    page.get_by_role("button", name="Verify & Enable MFA", exact=True).click()
    expect(page).to_have_url(re.compile(r"/mfa/backup-codes/$"))
    expect(page.locator("code")).to_have_count(8)
    codes = page.locator("code").all_text_contents()
    assert len(set(codes)) == 8
    assert all(re.fullmatch(r"[0-9]{8}", code) for code in codes)
    return codes
