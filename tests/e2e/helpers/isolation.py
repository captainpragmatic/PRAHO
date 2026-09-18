"""Cross-customer authorization against real, independently owned resources."""

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, ComprehensivePageMonitor, ensure_fresh_session, login_user


def verify_isolation(page: Page, baseline: dict, resource: str) -> None:
    customers = baseline["customers"]
    with ComprehensivePageMonitor(page, f"{resource} ownership", check_console=False, check_network=False) as monitor:
        monitor.add_expected_error_patterns(
            [
                "not found or access denied",
                "Ticket not found",
                "API request failed: Invoice not found",
                "API request failed: Proforma not found",
            ]
        )
        for index, owner in enumerate(customers):
            other = customers[1 - index]
            ensure_fresh_session(page)
            assert login_user(page, owner["email"], "test123" if index == 0 else "admin123")
            if resource in ("invoice", "proforma"):
                prefix = f"/billing/{resource}s/"
                key = resource + "_number"
                own_text = owner["name"]
                other_text = other["name"]
            else:
                prefix = "/services/" if resource == "service" else "/tickets/"
                key = resource + "_id"
                own_text = (
                    f"E2E Hosting {index + 1}-01" if resource == "service" else f"E2E hosting help {index + 1}-01"
                )
                other_text = (
                    f"E2E Hosting {2 - index}-01" if resource == "service" else f"E2E hosting help {2 - index}-01"
                )
            own_url = f"{BASE_URL}{prefix}{owner[key]}/"
            response = page.goto(own_url)
            assert response.status == 200
            expect(page).to_have_url(own_url)
            expect(page.locator("#main-content")).to_contain_text(own_text)
            response = page.goto(f"{BASE_URL}{prefix}{other[key]}/")
            assert response.status < 500
            expect(page.locator("body")).to_contain_text(re.compile("not found|access denied|permission", re.I))
            expect(page.locator("#main-content")).not_to_contain_text(other_text)
            if resource in ("invoice", "proforma"):
                pdf = page.request.get(f"{BASE_URL}{prefix}{other[key]}/pdf/")
                assert not pdf.headers.get("content-type", "").startswith("application/pdf")
                assert not pdf.body().startswith(b"%PDF-")
            elif resource == "service":
                page.goto(f"{BASE_URL}{prefix}{other[key]}/request-action/")
                expect(page.locator("body")).to_contain_text(re.compile("not found|access denied|permission", re.I))
                expect(page.locator('select[name="action"], input[name="action"]')).to_have_count(0)
