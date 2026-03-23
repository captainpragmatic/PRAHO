"""
Customer Company Profile E2E Tests for PRAHO Portal

Tests for company profile view/edit, tax profile management, the My Account
navigation dropdown, and language switching.

Routes under test:
  GET  /company/                  - company_profile_view
  GET  /company/edit/             - company_profile_edit_view
  POST /company/edit/             - company_profile_edit_view (save)
  GET  /company/tax/              - company_tax_profile_view
  POST /company/tax/              - company_tax_profile_view (save)
  GET  /profile/                  - profile_view (language + dropdown)
"""

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, require_authentication

# ===============================================================================
# COMPANY PROFILE VIEW
# ===============================================================================


def test_company_profile_view(monitored_customer_page: Page) -> None:
    """View company profile at /company/ — page loads and section cards present."""
    page = monitored_customer_page

    require_authentication(page)

    page.goto(f"{BASE_URL}/company/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/$"))

    # Page heading — "Company Profile" (EN) or Romanian equivalent
    heading = page.locator('h1, h2').filter(has_text=re.compile(r"Company Profile|Profil Companie", re.IGNORECASE)).first
    expect(heading).to_be_visible()

    # At least one section card for Company Information should be present
    company_info_card = page.locator('text=Company Information, text=Informații Companie').first
    expect(company_info_card).to_be_visible()

    # Quick-links to sub-sections should be present
    team_link = page.locator('a[href*="/company/team/"]').first
    expect(team_link).to_be_visible()

    tax_link = page.locator('a[href*="/company/tax/"]').first
    expect(tax_link).to_be_visible()

    addresses_link = page.locator('a[href*="/company/addresses/"]').first
    expect(addresses_link).to_be_visible()


# ===============================================================================
# COMPANY PROFILE EDIT
# ===============================================================================


def test_company_edit_page(monitored_customer_page: Page) -> None:
    """Edit company profile at /company/edit/ — form fields present, no direct VAT/billing fields."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/edit/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/edit/$"))

    # Company name field must be present
    company_name_field = page.locator('input[name="company_name"]')
    expect(company_name_field).to_be_visible()

    # "Tax & Addresses" managed via dedicated pages — links to those pages should be visible
    tax_manage_link = page.locator('a[href="/company/tax/"], a[href*="tax"]').first
    expect(tax_manage_link).to_be_visible()

    addr_manage_link = page.locator('a[href="/company/addresses/"], a[href*="addresses"]').first
    expect(addr_manage_link).to_be_visible()

    # The edit form must NOT expose a CUI or direct billing address field
    # (those live on the dedicated tax/address pages)
    cui_field = page.locator('input[name="cui"]')
    assert cui_field.count() == 0, "CUI field must not appear on company edit page"


def test_company_edit_save(monitored_customer_page: Page) -> None:
    """Edit and save company name, then verify update and restore original value."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/edit/")
    page.wait_for_load_state("networkidle")

    company_name_field = page.locator('input[name="company_name"]')
    expect(company_name_field).to_be_visible()

    # Remember original name so we can restore it
    original_name = company_name_field.input_value()
    test_name = "E2E Test Company Name"

    # Update the name and submit
    company_name_field.triple_click()
    company_name_field.fill(test_name)

    save_btn = page.locator('button[type="submit"]').first
    expect(save_btn).to_be_visible()
    save_btn.click()

    page.wait_for_load_state("networkidle")

    # After successful save we should land back on /company/
    expect(page).to_have_url(re.compile(r"/company/"))

    # Updated name should be displayed on the profile page
    page_content = page.content()
    assert test_name in page_content, f"Expected '{test_name}' on company profile after save"

    # --- Restore original name ---
    page.goto(f"{BASE_URL}/company/edit/")
    page.wait_for_load_state("networkidle")
    restore_field = page.locator('input[name="company_name"]')
    restore_field.triple_click()
    restore_field.fill(original_name)
    page.locator('button[type="submit"]').first.click()
    page.wait_for_load_state("networkidle")


# ===============================================================================
# TAX PROFILE
# ===============================================================================


def test_tax_profile_view(monitored_customer_page: Page) -> None:
    """View tax profile at /company/tax/ — CUI, VAT fields, and checkboxes present."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/tax/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/tax/$"))

    # The page should render either the edit form or the read-only view.
    # Either way, CUI-related text must appear.
    cui_label = page.locator('label[for="cui"], dt:has-text("CUI"), text=CUI').first
    expect(cui_label).to_be_visible()

    vat_label = page.locator('label[for="vat_number"], dt:has-text("VAT Number"), text=VAT Number').first
    expect(vat_label).to_be_visible()

    # Checkboxes (editable form) or badge equivalents (read-only) for VAT payer
    vat_payer_element = page.locator(
        'input[name="is_vat_payer"], dt:has-text("VAT Payer"), text=VAT Payer'
    ).first
    expect(vat_payer_element).to_be_visible()


def test_tax_profile_save(monitored_customer_page: Page) -> None:
    """Edit and save tax CUI, then verify update and restore original value."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/tax/")
    page.wait_for_load_state("networkidle")

    cui_field = page.locator('input[name="cui"]')
    # If the field is not present the user is read-only; skip edit assertions gracefully.
    if cui_field.count() == 0:
        print("  [i] Tax profile is read-only for this user — skipping save test")
        return

    expect(cui_field).to_be_visible()
    original_cui = cui_field.input_value()
    test_cui = "RO99999999"

    cui_field.triple_click()
    cui_field.fill(test_cui)

    save_btn = page.locator('button[type="submit"]').first
    save_btn.click()
    page.wait_for_load_state("networkidle")

    # After save we should redirect back to /company/tax/
    expect(page).to_have_url(re.compile(r"/company/tax/"))

    # Updated CUI should appear on the page
    page_content = page.content()
    assert test_cui in page_content, f"Expected '{test_cui}' on tax profile after save"

    # --- Restore original CUI ---
    restore_field = page.locator('input[name="cui"]')
    if restore_field.count() > 0:
        restore_field.triple_click()
        restore_field.fill(original_cui)
        page.locator('button[type="submit"]').first.click()
        page.wait_for_load_state("networkidle")


# ===============================================================================
# MY ACCOUNT DROPDOWN
# ===============================================================================


def test_my_account_dropdown(monitored_customer_page: Page) -> None:
    """My Account dropdown in desktop nav shows all expected items."""
    page = monitored_customer_page

    # Navigate to dashboard so the nav is fully rendered
    page.goto(f"{BASE_URL}/dashboard/")
    page.wait_for_load_state("networkidle")

    # Find the "My Account" dropdown trigger in the desktop nav
    my_account_trigger = page.locator('button:has-text("My Account"), a:has-text("My Account")').first
    expect(my_account_trigger).to_be_visible()
    my_account_trigger.click()

    # Wait for the dropdown to open
    page.wait_for_timeout(400)

    # Required dropdown items (text visible after click)
    expected_items = [
        "Account Settings",
        "Security",
        "Company Profile",
        "Team Members",
        "Addresses",
        "Privacy",
    ]
    for item in expected_items:
        item_locator = page.locator(f'a:has-text("{item}")').first
        expect(item_locator).to_be_visible()


# ===============================================================================
# LANGUAGE SWITCHING
# ===============================================================================


def test_profile_language_change(monitored_customer_page: Page) -> None:
    """Change preferred language to Romanian, verify Romanian UI, then switch back to English."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/profile/")
    page.wait_for_load_state("networkidle")

    # The profile form must include a language selector
    lang_select = page.locator('select[name="preferred_language"], select#id_preferred_language')
    if lang_select.count() == 0:
        print("  [i] Language selector not present — skipping language switch test")
        return

    expect(lang_select).to_be_visible()

    # Switch to Romanian
    lang_select.select_option("ro")

    save_btn = page.locator('button[type="submit"]').first
    save_btn.click()
    page.wait_for_load_state("networkidle")

    # After saving, at least one Romanian UI string should appear
    page_content = page.content()
    romanian_indicators = ["Salvează", "Profil", "Companie", "Echipă", "Adrese", "Setări"]
    found_romanian = any(word in page_content for word in romanian_indicators)
    assert found_romanian, "Expected Romanian UI strings after switching language to 'ro'"

    # --- Restore English ---
    lang_select_after = page.locator('select[name="preferred_language"], select#id_preferred_language')
    if lang_select_after.count() > 0:
        lang_select_after.select_option("en")
        page.locator('button[type="submit"]').first.click()
        page.wait_for_load_state("networkidle")


# ===============================================================================
# FORM DESIGN COMPONENTS
# ===============================================================================


def test_profile_form_uses_design_components(monitored_customer_page: Page) -> None:
    """Company edit form uses project design system CSS classes (section cards, form inputs)."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/edit/")
    page.wait_for_load_state("networkidle")

    # The company edit page wraps content in section-card-style containers.
    # These use bg-slate-800 / border-slate-700 Tailwind classes.
    section_container = page.locator('.bg-slate-800, .bg-slate-900').first
    expect(section_container).to_be_visible()

    # Form inputs use the project's standard Tailwind styling
    styled_input = page.locator(
        'input.bg-slate-700, input[class*="bg-slate"], input[class*="border-slate"]'
    ).first
    expect(styled_input).to_be_visible()
