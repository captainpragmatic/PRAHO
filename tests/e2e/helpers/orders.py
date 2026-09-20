"""Purchasable, known catalog inputs and observable checkout outcomes."""

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers.constants import BASE_URL


def add_product(page: Page) -> bool:
    page.goto(f"{BASE_URL}/order/")
    form = page.locator("#cart-form-e2e-hosting")
    expect(form).to_be_visible()
    form.get_by_role("button", name="Add to Cart", exact=True).click()
    expect(page.locator("#cart-count")).to_contain_text(re.compile(r"[1-9]"))
    return True


def bank_checkout(page: Page) -> str:
    page.goto(f"{BASE_URL}/order/checkout/")
    expect(page).to_have_url(re.compile(r"/order/checkout/$"))
    page.locator('input[name="payment_method"][value="bank_transfer"]').check()
    page.locator('input[name="agree_terms"]').check()
    page.locator("#checkout-submit").click()
    expect(page).to_have_url(re.compile(r"/order/confirmation/[^/]+/$"))
    expect(page.locator("#main-content")).to_contain_text(re.compile(r"ORD-\d+"))
    expect(page.get_by_role("heading", name="Awaiting your bank transfer")).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text("RO49AAAA1B31007593840000")
    expect(page.locator("#main-content")).to_contain_text("VAT (21%)")
    confirmation = page.url
    page.reload()
    expect(page).to_have_url(confirmation)
    expect(page.locator("#main-content")).to_contain_text(re.compile(r"ORD-\d+"))
    return confirmation
