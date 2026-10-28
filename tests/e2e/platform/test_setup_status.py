"""Administrators can follow setup remediation links and inspect ongoing health."""

import json

from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL


def test_replacing_an_unreadable_credential_clears_its_repair_warning(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/settings/backup/")
    row = page.locator('[id="setting-backup.aws_secret_access_key"]')
    expect(row.get_by_text("○  Not configured", exact=True)).to_be_visible()
    # Backend tests supply real unreadable ciphertext. Here the same initial state
    # exercises the actual browser controller and credential replacement endpoint.
    row.evaluate("element => { Alpine.$data(element).unreadable = true; }")
    warning = row.get_by_text("Stored value cannot be read.", exact=False)
    expect(warning).to_be_visible()
    expect(row.get_by_role("button", name="Clear", exact=True)).to_be_visible()
    csrf = page.locator('[name="csrfmiddlewaretoken"]').first.input_value()
    try:
        row.get_by_role("button", name="Replace…", exact=True).click()
        row.locator('input[type="password"]').fill("e2e-recovery-fixture-secret")
        with page.expect_response(lambda response: "/settings/secret/backup.aws_secret_access_key/" in response.url) as saved:
            row.get_by_role("button", name="Save", exact=True).click()
        assert saved.value.ok
        assert saved.value.json()["success"] is True
        expect(warning).not_to_be_visible()
        expect(row.get_by_text("●  Configured", exact=True)).to_be_visible()
        expect(row.locator('input[type="password"]')).to_have_value("")
    finally:
        cleared = page.request.post(f"{PLATFORM_BASE_URL}/settings/secret/backup.aws_secret_access_key/clear/",
                                    data=json.dumps({"reason": "Remove this test's fixture credential"}),
                                    headers={"Content-Type": "application/json", "X-CSRFToken": csrf, "Origin": PLATFORM_BASE_URL})
        assert cleared.ok
        assert cleared.json()["success"] is True


def test_setup_remediation_opens_and_scrolls_to_the_exact_setting(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/settings/setup/")
    expect(page.get_by_role("heading", name="Setup checklist", exact=True)).to_be_visible()
    page.get_by_role("link", name="Company identity", exact=True).click()
    expect(page).to_have_url(f"{PLATFORM_BASE_URL}/settings/company/?return_to=setup#setting-company.legal_name")
    setting = page.locator('[id="setting-company.legal_name"]')
    expect(setting).to_be_in_viewport()
    expect(setting.get_by_role("textbox")).to_be_visible()


def test_system_status_explains_freshness_and_bounded_resource_history(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/system-status/")
    expect(page.get_by_role("heading", name="System Status", exact=True)).to_be_visible()
    expect(page.get_by_text("Automatic checks run every ten minutes.", exact=False)).to_be_visible()
    expect(page.get_by_role("heading", name="Hourly resource summaries", exact=True)).to_be_visible()
    expect(page.get_by_role("columnheader", name="Samples (CPU / RAM / Disk)", exact=True)).to_be_visible()


def test_node_creation_explains_missing_cloudflare_access_and_links_to_its_setting(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/infrastructure/deployments/create/")
    expect(page.get_by_role("heading", name="Before you deploy a node", exact=True)).to_be_visible()
    dns = page.get_by_role("link", name="Configure Cloudflare API token", exact=True)
    expect(dns).to_have_attribute("href", "/settings/node-deployment/?return_to=node-deploy#setting-node_deployment.dns_cloudflare_api_token")
    dns.click()
    expect(page.locator('[id="setting-node_deployment.dns_cloudflare_api_token"]')).to_be_in_viewport()
