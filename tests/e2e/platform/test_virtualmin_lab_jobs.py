"""Browser smoke tests, staff side: the migrate form and a failed job's Retry (make test-virtualmin-e2e).

Migrate: the form submits, the account page shows the migration's progress and the domain ends up on the other
node. Retry: Webmin is stopped so a suspension fails before the node saw it, then started again; the job page
offers Retry, the click queues another attempt, the server's worker runs it and the node disables the domain.
Each test has its own account, and Webmin is started again whatever happens.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from apps.provisioning.virtualmin_gateway import listing_enabled
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from tests.e2e.helpers.virtualmin_lab import (
    MIGRATION_TIMEOUT_S,
    account_url,
    click_and_confirm,
    eventually,
    hosted_account,
    job_url,
    reload_until_text,
    until,
    wait_for_job,
)
from tests.virtualmin_lab.contract.harness import Lab
from tests.virtualmin_lab.workflows.harness import Bench

pytestmark = pytest.mark.virtualmin_lab


def node_answers(lab: Lab) -> bool:
    try:
        lab.domain_names()
    except AssertionError:  # the gateway refused or got no answer: Webmin is not up yet
        return False
    return True


def test_the_migrate_form_moves_the_account_and_the_page_shows_the_progress(
    lab_staff_page: Page, lab_bench: Bench
) -> None:
    domain = "wfe2emigrate.example.com"
    page = lab_staff_page
    with hosted_account(lab_bench, domain, node="vm-a") as account:
        assert lab_bench.key_of(account.server) == "vm-a"
        page.goto(account_url(account.pk))

        page.get_by_role("link", name="Migrate account").click()
        expect(page.locator("main h1")).to_contain_text("Migrate Virtualmin account")
        target = page.locator('select[name="target_server"] option').filter(has_text="vm-b")
        expect(target).to_have_count(1)
        page.locator('select[name="target_server"]').select_option(target.get_attribute("value"))
        page.locator('input[name="confirm"]').check()
        page.get_by_role("button", name="Start migration").click()

        # Back on the account page: queued, and a Migration section that moves on by itself.
        expect(page).to_have_url(account_url(account.pk))
        expect(page.locator("#toast-container")).to_contain_text("Migration queued")
        section = page.locator("section").filter(has=page.locator("h2", has_text="Migration"))
        expect(section).to_contain_text("Status:")
        reload_until_text(page, "section:has(h2:text-is('Migration'))", "Completed", timeout=MIGRATION_TIMEOUT_S,
                          what=f"the migration of {domain} to complete")
        expect(section).to_contain_text("Update routing/DNS manually")

        # PRAHO and the node agree: the account lives on vm-b, which hosts the domain and serves it enabled.
        account.refresh_from_db()
        assert lab_bench.key_of(account.server) == "vm-b"
        assert lab_bench.lab("vm-b").domain_exists(domain)
        assert listing_enabled(lab_bench.lab("vm-b").domain_values(domain)) is True


def test_a_failed_suspension_is_retried_from_its_job_page(lab_staff_page: Page, lab_bench: Bench) -> None:
    domain = "wfe2eretry.example.com"
    page = lab_staff_page
    with hosted_account(lab_bench, domain, node="vm-a") as account:
        lab = lab_bench.lab_of(account)
        lab.exec("systemctl", "stop", "webmin")
        try:
            page.goto(account_url(account.pk))
            click_and_confirm(page, page.get_by_role("button", name="Suspend", exact=True).click)
            expect(page.locator("#toast-container")).to_contain_text("is queued")

            # The reconcile's suspend job fails: Webmin refused the connection, so the node never saw it.
            job = eventually(
                lambda: VirtualminProvisioningJob.objects.filter(
                    account=account, operation="suspend_domain", status="failed"
                ).first(),
                timeout=180,
                what="the suspend job to fail while Webmin is stopped",
            )
        finally:
            lab.exec("systemctl", "start", "webmin")
        until(lambda: node_answers(lab), timeout=90, what="Webmin to answer again")

        page.goto(job_url(job.pk))
        expect(page.locator("dt:text-is('Status') + dd")).to_contain_text("Failed")
        expect(page.locator("main")).to_contain_text("Error Details")
        page.get_by_role("button", name="Retry Job").click()
        expect(page).to_have_url(re.compile(r"/jobs/[0-9a-f-]{36}/status/$"))
        expect(page.locator("#toast-container")).to_contain_text("The job is queued for another attempt.")

        wait_for_job(page, timeout=180, also_in_flight=("Failed",))
        job.refresh_from_db()
        assert job.status == "completed"
        assert listing_enabled(lab.domain_values(domain)) is False
        account.refresh_from_db()
        assert VirtualminAccount.objects.get(pk=account.pk).status == "suspended"
