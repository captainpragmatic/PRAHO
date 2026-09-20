"""
Customer Address & Team Management E2E Tests for PRAHO Portal

Tests for address CRUD, primary/billing designation, and team member management.

Routes under test:
  GET  /company/addresses/                          - addresses list
  GET  /company/addresses/add/                      - add address form
  POST /company/addresses/add/                      - create address
  POST /company/addresses/<id>/delete/              - delete address
  POST /company/addresses/<id>/set-primary/         - promote to primary
  POST /company/addresses/<id>/set-billing/         - promote to billing
  GET  /company/team/                               - team members list
  GET  /company/team/invite/                        - invite form
  POST /company/team/invite/                        - create invitation
  POST /company/team/<user_id>/remove/              - remove member
"""

import re
import uuid

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.helpers import (
    BASE_URL,
)

# ===============================================================================
# ADDRESS LIST
# ===============================================================================


def test_addresses_list(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/company/addresses/")
    expect(page.get_by_role("heading", name="Addresses", exact=True)).to_be_visible()
    address = page.locator("div.rounded-xl").filter(has_text="Str. Victoriei nr. 10")
    expect(address).to_contain_text("Primary")
    expect(address).to_contain_text("Billing")
    expect(address).to_contain_text("010061")


# ===============================================================================
# ADD ADDRESS
# ===============================================================================


def test_address_add(account_page) -> None:
    """Add a new address and verify it appears in the address list."""
    page, _ = account_page

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    # Find the "Add Address" button — only visible to owners
    add_btn = page.locator('a[href*="/company/addresses/add/"], a:has-text("Add Address")').first
    if add_btn.count() == 0:
        print("  [i] 'Add Address' button not present — user may not have owner role")
        pytest.fail("Required E2E step unavailable: add_btn.count() == 0")
    expect(add_btn).to_be_visible()
    add_btn.click()
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/addresses/add/$"))

    # Fill in the form with a unique label to identify the address later
    unique_label = f"E2E-{uuid.uuid4().hex[:6]}"

    page.locator('input[name="label"]').fill(unique_label)
    page.locator('input[name="address_line1"]').fill("Str. Test E2E nr. 1")
    page.locator('input[name="city"]').fill("București")
    page.locator('input[name="county"]').fill("Ilfov")
    page.locator('input[name="postal_code"]').fill("010101")
    # Country defaults to RO — leave as-is

    # Submit without marking is_primary or is_billing so it is safe to delete later.
    # Scope to the address form submit button by label to avoid the nav Logout button.
    save_btn = (
        page.locator('button[type="submit"]').filter(has_text=re.compile(r"Save Address|Salvează", re.IGNORECASE)).first
    )
    save_btn.click()
    page.wait_for_load_state("networkidle")

    # Should redirect back to addresses list
    expect(page).to_have_url(re.compile(r"/company/addresses/$"))

    # The new address should appear in the list
    page_content = page.content()
    assert unique_label in page_content or "Str. Test E2E" in page_content, (
        "Newly added address should appear in the addresses list"
    )

    # --- Clean up: delete the address we just added ---
    _delete_address_by_label(page, unique_label)


# ===============================================================================
# MAKE PRIMARY
# ===============================================================================


def test_address_make_primary(account_page) -> None:
    """Move the designation to a different address and verify it survives reload."""
    page, _account = account_page
    page.goto(f"{BASE_URL}/company/addresses/")
    target = page.locator("div.rounded-xl").filter(has_text="Str. Noua 20")
    target.get_by_role("button", name="Make Primary", exact=True).click()
    page.reload()
    expect(target).to_contain_text("Primary")
    expect(target.get_by_role("button", name="Make Primary", exact=True)).to_have_count(0)
    previous = page.locator("div.rounded-xl").filter(has_text="Str. Victoriei nr. 10")
    expect(previous.get_by_role("button", name="Make Primary", exact=True)).to_be_visible()


# ===============================================================================
# MAKE BILLING
# ===============================================================================


def test_address_make_billing(account_page) -> None:
    """Move the designation to a different address and verify it survives reload."""
    page, _account = account_page
    page.goto(f"{BASE_URL}/company/addresses/")
    target = page.locator("div.rounded-xl").filter(has_text="Str. Noua 20")
    target.get_by_role("button", name="Make Billing", exact=True).click()
    page.reload()
    expect(target).to_contain_text("Billing")
    expect(target.get_by_role("button", name="Make Billing", exact=True)).to_have_count(0)
    previous = page.locator("div.rounded-xl").filter(has_text="Str. Victoriei nr. 10")
    expect(previous.get_by_role("button", name="Make Billing", exact=True)).to_be_visible()


# ===============================================================================
# DELETE UNDESIGNATED ADDRESS
# ===============================================================================


def test_address_delete_undesignated(account_page) -> None:
    """Delete an address that is neither primary nor billing — address removed from list."""
    page, _ = account_page

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    add_btn = page.locator('a[href*="/company/addresses/add/"]').first
    if add_btn.count() == 0:
        print("  [i] Add Address not accessible — user may not have owner role")
        pytest.fail("Required E2E step unavailable: add_btn.count() == 0")

    # Create a temporary address without designating it primary or billing
    unique_label = f"DEL-{uuid.uuid4().hex[:6]}"

    add_btn.click()
    page.wait_for_load_state("networkidle")

    page.locator('input[name="label"]').fill(unique_label)
    page.locator('input[name="address_line1"]').fill("Str. Temp nr. 99")
    page.locator('input[name="city"]').fill("Cluj-Napoca")
    page.locator('input[name="postal_code"]').fill("400001")

    # Scope submit to the address form button to avoid the nav Logout button
    page.locator('button[type="submit"]').filter(
        has_text=re.compile(r"Save Address|Salvează", re.IGNORECASE)
    ).first.click()
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/addresses/$"))
    assert unique_label in page.content(), "Temp address should appear in list after creation"

    # Now delete it
    _delete_address_by_label(page, unique_label)

    # Verify it's gone
    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")
    assert unique_label not in page.content(), "Deleted address should no longer appear in list"


# ===============================================================================
# DELETE PRIMARY BLOCKED
# ===============================================================================


def test_address_delete_primary_blocked(monitored_customer_page: Page) -> None:
    """Primary address should NOT have a Delete button."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    # Find address cards that contain a "Primary" badge.
    # Use :has-text() (Playwright CSS extension) — NOT :has(text="...") which is invalid CSS.
    primary_cards = page.locator('div.bg-slate-800:has-text("Primary"), div.bg-slate-800:has-text("Primar")')
    if primary_cards.count() == 0:
        print("  [i] No primary address found on the page — skipping delete-blocked check")
        pytest.fail("Required E2E step unavailable: primary_cards.count() == 0")

    # Within the primary card, no Delete button should exist
    primary_card = primary_cards.first
    delete_btn_in_primary = primary_card.locator('button:has-text("Delete"), button:has-text("Șterge")')
    assert delete_btn_in_primary.count() == 0, "Primary address must not have a Delete button visible"


# ===============================================================================
# NO "CURRENT" BADGE
# ===============================================================================


def test_address_no_current_badge(monitored_customer_page: Page) -> None:
    """'Current' text should not appear as a badge on the addresses page."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    # The address template uses Primary / Billing / Other badges — never "Current"
    current_badge = page.locator('text="Current"').first
    assert current_badge.count() == 0, "No 'Current' badge should appear on the addresses page"


# ===============================================================================
# TEAM MEMBERS LIST
# ===============================================================================


def test_team_members_list(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/company/team/")
    expect(page.get_by_role("heading", name="Team Members", exact=True)).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text(e2e_baseline["customers"][0]["email"])
    expect(page.locator("#main-content")).to_contain_text("Owner")
    expect(page.locator("#main-content")).not_to_contain_text(e2e_baseline["customers"][1]["email"])


# ===============================================================================
# INVITE TEAM MEMBER
# ===============================================================================


def test_team_invite_member(account_page) -> None:
    """Invite a new team member then clean up by removing them."""
    page, _ = account_page

    page.goto(f"{BASE_URL}/company/team/")
    page.wait_for_load_state("networkidle")

    invite_btn = page.locator('a[href*="/company/team/invite/"], a:has-text("Invite Member")').first
    if invite_btn.count() == 0:
        print("  [i] Invite Member button not present — user may not have owner role")
        pytest.fail("Required E2E step unavailable: invite_btn.count() == 0")

    expect(invite_btn).to_be_visible()
    invite_btn.click()
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/team/invite/$"))

    # Generate a unique email so we can identify the member in the list
    unique_suffix = uuid.uuid4().hex[:8]
    invite_email = f"e2e-invite-{unique_suffix}@test.local"
    invite_first = "E2EFirst"
    invite_last = "E2ELast"

    page.locator('input[name="email"]').fill(invite_email)
    page.locator('input[name="first_name"]').fill(invite_first)
    page.locator('input[name="last_name"]').fill(invite_last)
    page.locator('select[name="role"]').select_option("viewer")

    # Scope submit to the invite form button to avoid the nav Logout button
    page.locator('button[type="submit"]').filter(
        has_text=re.compile(r"Send Invitation|Invită|Trimite", re.IGNORECASE)
    ).first.click()
    page.wait_for_load_state("networkidle")

    # Should redirect to the team list on success
    expect(page).to_have_url(re.compile(r"/company/team/$"))

    # The invited member should appear in the list
    page_content = page.content()
    assert invite_email in page_content and invite_first in page_content, (
        "Invited member should appear in the team list after invitation"
    )

    # --- Clean up: remove the invited member ---
    page.reload()
    expect(page.locator("#main-content")).to_contain_text(invite_email)
    expect(page.locator("#main-content")).to_contain_text("Viewer")


# ===============================================================================
# INTERNAL HELPERS
# ===============================================================================


def _delete_address_by_label(page: Page, label: str) -> None:
    page.goto(f"{BASE_URL}/company/addresses/")
    page.once("dialog", lambda dialog: dialog.accept())
    card = page.locator("div.rounded-xl").filter(has_text=label)
    expect(card).to_have_count(1)
    card.locator('form[action*="delete"] button[type="submit"]').click()
    page.reload()
    expect(page.locator("#main-content")).not_to_contain_text(label)
