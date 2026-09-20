"""Customer billing contracts against known, separately owned documents."""

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, assert_responsive_results, run_responsive_breakpoints_test
from tests.e2e.helpers.isolation import verify_isolation


def _detail(page: Page, baseline: dict, kind: str = "invoice", *, paid: bool = False) -> dict:
    owner = baseline["customers"][0]
    number = owner["paid_invoice_number" if paid else f"{kind}_number"]
    url = f"{BASE_URL}/billing/{kind}s/{number}/"
    response = page.goto(url)
    assert response.status == 200
    expect(page).to_have_url(url)
    expect(page.locator("h1")).to_contain_text(number)
    expect(page.locator("#main-content")).to_contain_text(owner["name"])
    expect(page.locator("#main-content")).to_contain_text(re.compile(r"121[,.]00"))
    expect(page.locator("table")).to_contain_text("E2E hosting")
    return owner


def _pdf(page: Page) -> None:
    link = page.get_by_role("link", name="Download PDF")
    expect(link).to_be_visible()
    response = page.request.get(BASE_URL + link.get_attribute("href"))
    assert response.status == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.body().startswith(b"%PDF-")
    assert len(response.body()) > 1000


def _no_staff_controls(page: Page) -> None:
    for label in ("New Proforma", "Create Invoice", "Record Payment", "Convert to Invoice", "Send Email"):
        expect(page.get_by_role("button", name=label, exact=True)).to_have_count(0)
        expect(page.get_by_role("link", name=label, exact=True)).to_have_count(0)


def test_customer_billing_system_access_via_navigation(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/dashboard/")
    page.locator('a[href="/billing/invoices/"]:visible').first.click()
    expect(page).to_have_url(f"{BASE_URL}/billing/invoices/")
    expect(page.get_by_role("heading", name="My Billing Documents", exact=True)).to_be_visible()
    _no_staff_controls(page)


def test_customer_billing_list_display_own_invoices_only(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    own, other = e2e_baseline["customers"]
    for kind in ("invoice", "proforma"):
        page.goto(f"{BASE_URL}/billing/invoices/?q={own[kind + '_number']}")
        expect(page.locator("table")).to_contain_text(own[kind + "_number"])
        page.goto(f"{BASE_URL}/billing/invoices/?q={other[kind + '_number']}")
        expect(page.locator("#main-content")).not_to_contain_text(other[kind + "_number"])
        expect(page.locator("tr[data-href]")).to_have_count(0)
    _no_staff_controls(page)


def test_customer_invoice_detail_and_pdf_access(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    _detail(page, e2e_baseline)
    expect(page.locator("table")).to_contain_text("21,00 RON")
    _no_staff_controls(page)
    _pdf(page)


def test_customer_payment_status_and_history(monitored_customer_page: Page, e2e_baseline) -> None:
    """Paid and unpaid documents show their persisted settlement state and date."""
    page = monitored_customer_page
    _detail(page, e2e_baseline)
    payment_date = page.locator('dt:has-text("Payment Date") + dd')
    expect(payment_date).to_have_text("Not paid")
    expect(page.get_by_role("button", name="Request Refund")).to_have_count(0)
    _detail(page, e2e_baseline, paid=True)
    expect(payment_date).to_have_text(re.compile(r"\d{1,2} \w+\.? \d{4}, \d{2}:\d{2}"))
    expect(page.get_by_role("button", name="Request Refund")).to_be_visible()
    page.reload()
    expect(payment_date).not_to_contain_text("Not paid")


def test_customer_billing_access_control_security(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    for kind in ("invoice", "proforma"):
        _detail(page, e2e_baseline, kind)
        _no_staff_controls(page)


def test_customer_billing_isolation_comprehensive_security(page: Page, e2e_baseline) -> None:
    verify_isolation(page, e2e_baseline, "invoice")
    verify_isolation(page, e2e_baseline, "proforma")


def test_customer_cannot_access_other_customers_billing(page: Page, e2e_baseline) -> None:
    verify_isolation(page, e2e_baseline, "invoice")
    verify_isolation(page, e2e_baseline, "proforma")


def test_customer_billing_system_mobile_responsiveness(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.set_viewport_size({"width": 375, "height": 812})
    _detail(page, e2e_baseline)
    _pdf(page)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
        "Invoice overflows mobile viewport"
    )


def test_customer_complete_billing_workflow(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    number = e2e_baseline["customers"][0]["invoice_number"]
    page.goto(f"{BASE_URL}/billing/invoices/?q={number}")
    page.locator(f'tr[data-href="/billing/invoices/{number}/"]').click()
    expect(page.locator("h1")).to_contain_text(number)
    _pdf(page)
    expect(page.locator('dt:has-text("Payment Date") + dd')).to_have_text("Not paid")
    _no_staff_controls(page)
    page.get_by_role("link", name="Back to Billing").click()
    expect(page).to_have_url(f"{BASE_URL}/billing/invoices/")


def test_customer_billing_system_responsive_breakpoints(monitored_customer_page: Page, e2e_baseline) -> None:
    def check(page: Page, context: str = "") -> bool:
        _detail(page, e2e_baseline)
        expect(page.get_by_role("link", name="Download PDF")).to_be_visible()
        return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    assert_responsive_results(run_responsive_breakpoints_test(monitored_customer_page, check), "Billing document")


def test_customer_billing_proforma_detail_view(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    _detail(page, e2e_baseline, "proforma")
    expect(page.locator("#main-content")).to_contain_text("Proforma Valid")
    expect(page.get_by_role("button", name="Request Refund")).to_have_count(0)
    expect(page.get_by_role("link", name="Back to Billing")).to_be_visible()


def test_customer_billing_proforma_pdf_download(monitored_customer_page: Page, e2e_baseline) -> None:
    _detail(monitored_customer_page, e2e_baseline, "proforma")
    _pdf(monitored_customer_page)


def test_customer_billing_invoice_pdf_download(monitored_customer_page: Page, e2e_baseline) -> None:
    _detail(monitored_customer_page, e2e_baseline)
    _pdf(monitored_customer_page)


def test_customer_billing_dashboard_widget(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/dashboard/")
    expect(page.locator('a[href="/billing/invoices/"]:visible').first).to_be_visible()
    response = page.request.get(f"{BASE_URL}/billing/dashboard-widget/")
    assert response.status == 200
    data = response.json()
    assert data["success"] is True
    assert data["summary"]["total_invoices"] >= 25
    assert data["summary"]["pending_count"] >= 13
    assert data["summary"]["total_due_cents"] >= 13 * 12100
    assert len(data["summary"]["recent_invoices"]) == 3


def test_customer_billing_sync_button(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/billing/invoices/")
    with page.expect_response(re.compile(r"/billing/sync/$")) as result:
        page.locator('button[hx-post="/billing/sync/"]:visible').first.click()
    response = result.value
    assert response.status == 200
    data = response.json()
    assert data["success"] is True
    assert data["synced_count"] >= 25
    _detail(page, e2e_baseline)
