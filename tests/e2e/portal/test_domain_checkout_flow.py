"""An individual's domain order collects registry identity and accepts a transfer code."""
import re
from collections.abc import Callable

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, ensure_fresh_session, login_user
from tests.e2e.helpers.csp import install_csp_violation_capture, read_csp_violations


def test_domain_checkout_and_transfer_code(page: Page, e2e_scenario: Callable[[str], dict[str, str | int]]) -> None:
    account = e2e_scenario("domain_checkout")
    install_csp_violation_capture(page)
    ensure_fresh_session(page)
    assert login_user(page, str(account["email"]), str(account["password"]))
    product_url = f"{BASE_URL}/order/products/{account['product_slug']}/"
    page.goto(product_url)
    expect(page).to_have_url(product_url)
    page.locator('[name="domain_name"]').fill(str(account["registration_domain"]))
    with page.expect_response(lambda response: response.url.endswith("/order/domains/availability/")):
        page.get_by_role("button", name="Check availability", exact=True).click()
    expect(page.locator("#domain-availability")).to_contain_text("Could not verify domain availability")
    assert read_csp_violations(page) == []
    page.get_by_role("button", name="Add to Cart", exact=True).click()
    expect(page.locator("#cart-count")).to_contain_text("1")
    page.goto(product_url)
    expect(page).to_have_url(product_url)
    page.locator('[name="domain_name"]').fill(str(account["transfer_domain"]))
    page.locator('[name="domain_mode"]').select_option("transfer")
    page.get_by_role("button", name="Add to Cart", exact=True).click()
    expect(page.locator("#cart-count")).to_contain_text("2")
    page.goto(f"{BASE_URL}/order/checkout/")
    expect(page.locator("#main-content")).to_contain_text(str(account["registration_domain"]))
    expect(page.locator("#main-content")).to_contain_text(str(account["transfer_domain"]))
    expect(page.locator('[name="cnp"]')).to_be_visible()
    expect(page.get_by_role("button", name="Create order", exact=True)).to_be_disabled()
    expect(page.locator("#main-content")).to_contain_text("proformas, invoices and e-Factura")
    page.locator('[name="cnp"]').fill("1850101123450")
    page.get_by_role("button", name="Save registrant identity", exact=True).click()
    expect(page.locator('[name="cnp"]')).to_have_value("")
    expect(page.get_by_role("button", name="Create order", exact=True)).to_be_disabled()
    page.locator('[name="cnp"]').fill("1850101123451")
    page.get_by_role("button", name="Save registrant identity", exact=True).click()
    expect(page.locator('[name="cnp"]')).to_have_count(0)
    expect(page.locator("#checkout-submit")).to_be_enabled()
    assert read_csp_violations(page) == []
    page.locator('[name="payment_method"][value="bank_transfer"]').check()
    page.locator('[name="agree_terms"]').check()
    page.locator('[name="early_start_requested"]').check()
    page.locator("#checkout-submit").click()
    expect(page).to_have_url(re.compile(r"/order/confirmation/[^/]+/$"))
    expect(page.get_by_role("heading", name="Awaiting your bank transfer")).to_be_visible()
    expect(page.locator('[name="transfer_code"]')).to_be_visible()
    page.locator('[name="transfer_code"]').fill("Synthetic-Transfer!123")
    page.get_by_role("button", name="Save transfer code", exact=True).click()
    expect(page.locator('[name="transfer_code"]')).to_have_value("")
    expect(page.locator("#main-content")).not_to_contain_text("Synthetic-Transfer!123")
    assert read_csp_violations(page) == []
