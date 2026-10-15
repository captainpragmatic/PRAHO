"""Browser smoke tests, staff side: backups, the differential chain and the pair restore (make test-virtualmin-e2e).

A full backup is requested through the form and followed on the job page until it completes; the base and
differential buttons and the restore-pair page follow with the opt-in flag on (the runner starts the server
with it). The node is asked afterwards: its staging directory is empty once an archive is published, and a
pair restore brings back the data as the differential held it.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterator

import pytest
from playwright.sync_api import Page, expect

from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from tests.e2e.helpers.virtualmin_lab import (
    account_url,
    click_and_confirm,
    hosted_account,
    job_id_from,
    job_url,
    wait_for_job,
)
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

pytestmark = pytest.mark.virtualmin_lab

DOMAIN = "wfe2ebackup.example.com"
JOB_URL = re.compile(r"/provisioning/virtualmin/jobs/[0-9a-f-]{36}/status/$")


@pytest.fixture(scope="module")
def account(lab_bench: Bench) -> Iterator[VirtualminAccount]:
    with hosted_account(lab_bench, DOMAIN) as hosted:
        yield hosted


def follow_job(page: Page) -> None:
    """The click swapped the job page into this one (the address bar did not move): open it and wait for the end."""
    expect(page.locator("main h1")).to_contain_text("Job Status")
    page.goto(job_url(job_id_from(page)))
    wait_for_job(page)


def job_of(page: Page) -> VirtualminProvisioningJob:
    return VirtualminProvisioningJob.objects.get(pk=job_id_from(page))


def test_a_full_backup_runs_to_completion_from_the_backup_form(
    lab_staff_page: Page, lab_bench: Bench, account: VirtualminAccount
) -> None:
    page = lab_staff_page
    data = DomainData(lab_bench.lab_of(account), account)
    data.seed(secrets.token_hex(6))
    data.add_blob(24)  # incompressible bulk: the backup takes seconds, so the page is seen mid-flight
    page.goto(account_url(account.pk))

    page.get_by_role("link", name="Backup Now").click()
    expect(page.locator("main h1")).to_contain_text(f"Backup Account: {DOMAIN}")
    page.get_by_role("button", name="Create Backup").click()

    # Submitted: the job page, with the queued message and progress that moves on without the test's help.
    expect(page).to_have_url(JOB_URL)
    expect(page.locator("#toast-container")).to_contain_text("Backup job created successfully")
    expect(page.locator("main h1")).to_contain_text("Job Status")
    expect(page.locator("#job-logs")).to_contain_text("Job created")
    wait_for_job(page)
    expect(page.locator("main")).to_contain_text("Response Data")
    expect(page.locator("main")).to_contain_text("backup_id")

    # PRAHO: the job and the archive it published. The node: nothing is left in the staging directory.
    job = job_of(page)
    assert (job.operation, job.status) == ("backup_domain", "completed"), (job.operation, job.status)
    manifest = VirtualminBackupService(account.server).read_manifest(job.result["backup_id"]).unwrap()
    assert (manifest["domain"], manifest["backup_type"]) == (DOMAIN, "full")
    assert lab_bench.staged(account) == []
    data.remove("blob.bin")

    # The account page lists it, with a Restore button.
    page.goto(account_url(account.pk))
    page.get_by_role("button", name="Backups").click()
    expect(page.get_by_role("link", name="Restore").first).to_be_visible()


def test_base_then_differential_then_the_pair_restore_page(
    lab_staff_page: Page, lab_bench: Bench, account: VirtualminAccount
) -> None:
    page = lab_staff_page
    lab = lab_bench.lab_of(account)
    data = DomainData(lab, account)
    data.seed(secrets.token_hex(6))
    data.write("change.txt", "v0")
    page.goto(account_url(account.pk))

    # Take base backup: the confirm dialog says it starts a chain, then the job completes.
    asked = click_and_confirm(page, page.get_by_role("button", name="Take base backup").click)
    assert "starts a new chain" in asked
    expect(page.locator("#toast-container")).to_contain_text("Base backup queued.")
    follow_job(page)
    base = job_of(page)
    assert base.parameters["chain_role"] == "base"

    # Change the data, then take the differential: the dialog says it needs the base to restore.
    data.write("change.txt", "v1")
    data.write("added.txt", "added after the base")
    page.goto(account_url(account.pk))
    asked = click_and_confirm(page, page.get_by_role("button", name="Take differential backup").click)
    assert "restoring it needs that base backup" in asked
    expect(page.locator("#toast-container")).to_contain_text("Differential backup queued.")
    follow_job(page)
    differential = job_of(page)
    assert differential.parameters["base_backup_id"] == base.result["backup_id"], "the differential names its base"
    assert lab_bench.staged(account) == []

    # The restore-pair page says in plain words what the restore does, before anything is chosen.
    data.write("change.txt", "damaged")
    data.remove("added.txt")
    page.goto(account_url(account.pk))
    page.get_by_role("link", name="Restore pair").click()
    expect(page.locator("main h1")).to_contain_text(f"Restore pair: {DOMAIN}")
    warning = page.locator("main .bg-yellow-900\\/20")
    expect(warning).to_contain_text("Restores the base backup and then the differential.")
    expect(warning).to_contain_text("Files deleted after the base was taken will reappear")
    expect(warning).to_contain_text("The domain is taken offline")
    expect(page.locator("#id_differential_id")).to_contain_text(differential.result["backup_id"])

    # Without the confirmation nothing is queued; with it the pair runs and the data comes back as the differential held it.
    page.get_by_role("button", name="Restore pair").click()
    expect(page).not_to_have_url(JOB_URL)
    page.locator('input[name="confirm_restore"]').check()
    page.get_by_role("button", name="Restore pair").click()
    expect(page).to_have_url(JOB_URL)
    expect(page.locator("#toast-container")).to_contain_text("Pair restore queued.")
    wait_for_job(page)
    assert data.read("change.txt") == "v1"
    assert data.read("added.txt") == "added after the base"
    assert lab_bench.lab_of(account).domain_exists(DOMAIN)
