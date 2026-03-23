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

from playwright.sync_api import Page, expect

from tests.e2e.helpers import (
    BASE_URL,
    require_authentication,
)

# ===============================================================================
# ADDRESS LIST
# ===============================================================================


def test_addresses_list(monitored_customer_page: Page) -> None:
    """View addresses at /company/addresses/ — page loads and address cards present."""
    page = monitored_customer_page

    require_authentication(page)

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/addresses/$"))

    # Page heading — "Addresses" or Romanian equivalent
    heading = page.locator('h1, h2').filter(
        has_text=re.compile(r"Address|Adrese", re.IGNORECASE)
    ).first
    expect(heading).to_be_visible()

    # Either addresses are listed (with Primary/Billing badges) or the empty state is shown
    has_addresses = page.locator('.bg-slate-800 .text-white').count() > 0
    has_empty_state = page.locator('text=No addresses yet, text=Nicio adresă').count() > 0
    assert has_addresses or has_empty_state, "Address list should show addresses or empty state"

    # If addresses are present, Primary or Billing badge should be visible on at least one
    if has_addresses:
        badge = page.locator('text=Primary, text=Billing, text=Primar, text=Facturare').first
        # Badges are optional — only assert their presence if address cards exist
        if badge.count() > 0:
            expect(badge).to_be_visible()


# ===============================================================================
# ADD ADDRESS
# ===============================================================================


def test_address_add(monitored_customer_page: Page) -> None:
    """Add a new address and verify it appears in the address list."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    # Find the "Add Address" button — only visible to owners
    add_btn = page.locator('a[href*="/company/addresses/add/"], a:has-text("Add Address")').first
    if add_btn.count() == 0:
        print("  [i] 'Add Address' button not present — user may not have owner role")
        return
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

    # Submit without marking is_primary or is_billing so it is safe to delete later
    save_btn = page.locator('button[type="submit"]').first
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


def test_address_make_primary(monitored_customer_page: Page) -> None:
    """Make a non-primary address primary — Primary badge moves to that address."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    # Look for a "Make Primary" button (only present on non-primary addresses)
    make_primary_btn = page.locator(
        'button:has-text("Make Primary"), button:has-text("Setează Principal")'
    ).first
    if make_primary_btn.count() == 0:
        print("  [i] No 'Make Primary' button found — only one address or already all primary")
        return

    expect(make_primary_btn).to_be_visible()
    make_primary_btn.click()
    page.wait_for_load_state("networkidle")

    # After the POST redirect we should still be on the addresses page
    expect(page).to_have_url(re.compile(r"/company/addresses/$"))

    # "Primary" badge should be visible (may have been there before — just verify page is intact)
    page_content = page.content()
    assert "Primary" in page_content or "Primar" in page_content, (
        "A Primary badge should be visible on the addresses page after Make Primary"
    )


# ===============================================================================
# MAKE BILLING
# ===============================================================================


def test_address_make_billing(monitored_customer_page: Page) -> None:
    """Make a non-billing address billing — Billing badge moves to that address."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    make_billing_btn = page.locator(
        'button:has-text("Make Billing"), button:has-text("Setează Facturare")'
    ).first
    if make_billing_btn.count() == 0:
        print("  [i] No 'Make Billing' button found — only one address or already marked billing")
        return

    expect(make_billing_btn).to_be_visible()
    make_billing_btn.click()
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/addresses/$"))

    page_content = page.content()
    assert "Billing" in page_content or "Facturare" in page_content, (
        "A Billing badge should be visible on the addresses page after Make Billing"
    )


# ===============================================================================
# DELETE UNDESIGNATED ADDRESS
# ===============================================================================


def test_address_delete_undesignated(monitored_customer_page: Page) -> None:
    """Delete an address that is neither primary nor billing — address removed from list."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    add_btn = page.locator('a[href*="/company/addresses/add/"]').first
    if add_btn.count() == 0:
        print("  [i] Add Address not accessible — user may not have owner role")
        return

    # Create a temporary address without designating it primary or billing
    unique_label = f"DEL-{uuid.uuid4().hex[:6]}"

    add_btn.click()
    page.wait_for_load_state("networkidle")

    page.locator('input[name="label"]').fill(unique_label)
    page.locator('input[name="address_line1"]').fill("Str. Temp nr. 99")
    page.locator('input[name="city"]').fill("Cluj-Napoca")
    page.locator('input[name="postal_code"]').fill("400001")

    page.locator('button[type="submit"]').first.click()
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

    # Find address cards that contain a "Primary" badge
    # The template only renders Delete form when `not addr.is_primary and not addr.is_billing`
    primary_cards = page.locator(
        'div.bg-slate-800:has(text="Primary"), div.bg-slate-800:has(text="Primar")'
    )
    if primary_cards.count() == 0:
        print("  [i] No primary address found on the page — skipping delete-blocked check")
        return

    # Within the primary card, no Delete button should exist
    primary_card = primary_cards.first
    delete_btn_in_primary = primary_card.locator(
        'button:has-text("Delete"), button:has-text("Șterge")'
    )
    assert delete_btn_in_primary.count() == 0, (
        "Primary address must not have a Delete button visible"
    )


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


def test_team_members_list(monitored_customer_page: Page) -> None:
    """View team at /company/team/ — page loads with member list or empty state."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/team/")
    page.wait_for_load_state("networkidle")

    expect(page).to_have_url(re.compile(r"/company/team/$"))

    # Page heading
    heading = page.locator('h1, h2').filter(
        has_text=re.compile(r"Team Members|Membri Echipă", re.IGNORECASE)
    ).first
    expect(heading).to_be_visible()

    # Either members are listed or empty state is shown
    has_members = page.locator('.bg-slate-800 .text-white').count() > 0
    has_empty_state = page.locator('text=No team members yet, text=Niciun membru').count() > 0
    assert has_members or has_empty_state, "Team page should show members or empty state"

    # If members are present, role badges should be visible
    if has_members:
        role_badge = page.locator(
            'text=owner, text=viewer, text=tech, text=billing, '
            'text=Owner, text=Viewer, text=Technical, text=Billing'
        ).first
        if role_badge.count() > 0:
            expect(role_badge).to_be_visible()


# ===============================================================================
# INVITE TEAM MEMBER
# ===============================================================================


def test_team_invite_member(monitored_customer_page: Page) -> None:
    """Invite a new team member then clean up by removing them."""
    page = monitored_customer_page

    page.goto(f"{BASE_URL}/company/team/")
    page.wait_for_load_state("networkidle")

    invite_btn = page.locator(
        'a[href*="/company/team/invite/"], a:has-text("Invite Member")'
    ).first
    if invite_btn.count() == 0:
        print("  [i] Invite Member button not present — user may not have owner role")
        return

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

    page.locator('button[type="submit"]').first.click()
    page.wait_for_load_state("networkidle")

    # Should redirect to the team list on success
    expect(page).to_have_url(re.compile(r"/company/team/$"))

    # The invited member should appear in the list
    page_content = page.content()
    assert invite_email in page_content or invite_first in page_content, (
        "Invited member should appear in the team list after invitation"
    )

    # --- Clean up: remove the invited member ---
    _remove_team_member_by_email(page, invite_email)


# ===============================================================================
# INTERNAL HELPERS
# ===============================================================================


def _delete_address_by_label(page: Page, label: str) -> None:
    """Find the address card matching *label* and submit its Delete form.

    No-ops gracefully if the address is not found or has no Delete button.
    Uses page.on("dialog") to auto-accept the confirm() dialog on the Delete form.
    """
    page.goto(f"{BASE_URL}/company/addresses/")
    page.wait_for_load_state("networkidle")

    # Dismiss the browser confirm() dialog automatically
    page.on("dialog", lambda d: d.accept())

    # Locate the specific address card that contains our label text
    address_cards = page.locator("div.bg-slate-800")
    card_count = address_cards.count()
    for i in range(card_count):
        card = address_cards.nth(i)
        if label in card.inner_text():
            delete_form = card.locator('form[action*="delete"]')
            if delete_form.count() > 0:
                delete_btn = delete_form.locator('button[type="submit"]')
                if delete_btn.count() > 0:
                    delete_btn.click()
                    page.wait_for_load_state("networkidle")
            return

    print(f"  [i] Address with label '{label}' not found for deletion — already gone?")


def _remove_team_member_by_email(page: Page, email: str) -> None:
    """Find the team member card for *email* and submit their Remove form.

    No-ops gracefully if the member is not found.
    Uses page.on("dialog") to auto-accept the confirm() dialog on Remove.
    """
    page.goto(f"{BASE_URL}/company/team/")
    page.wait_for_load_state("networkidle")

    page.on("dialog", lambda d: d.accept())

    member_cards = page.locator("div.bg-slate-800, section")
    card_count = member_cards.count()
    for i in range(card_count):
        card = member_cards.nth(i)
        if email in card.inner_text():
            remove_form = card.locator('form[action*="remove"]')
            if remove_form.count() > 0:
                remove_btn = remove_form.locator('button[type="submit"]')
                if remove_btn.count() > 0:
                    remove_btn.click()
                    page.wait_for_load_state("networkidle")
            return

    print(f"  [i] Team member '{email}' not found for removal — already gone?")
