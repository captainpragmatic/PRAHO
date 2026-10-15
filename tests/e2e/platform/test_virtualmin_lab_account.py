"""Browser smoke tests, staff side: a real lab account, its page, Suspend and Activate (make test-virtualmin-e2e).

Each test drives the staff pages in a real browser and then asks the node (`list-domains`, through the lab
helper): the page says what PRAHO recorded, the node says what happened. The server runs inside the lab
transport with a worker thread (tests/virtualmin_lab/run_e2e.sh), so a click that queues work really reaches
the node and the page moves on by itself. The tests wait for that with retrying expects and polls, never with
a fixed sleep, and never drain the queue themselves.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest
from django.utils import timezone
from playwright.sync_api import Page, expect

from apps.provisioning.virtualmin_gateway import listing_enabled
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.e2e.helpers import PLATFORM_BASE_URL
from tests.e2e.helpers.virtualmin_lab import (
    JOB_TIMEOUT_S,
    account_url,
    click_and_confirm,
    hosted_account,
    reload_until_text,
    until,
)
from tests.virtualmin_lab.workflows.harness import Bench

pytestmark = pytest.mark.virtualmin_lab

DOMAIN = "wfe2eacct.example.com"


@pytest.fixture(scope="module")
def account(lab_bench: Bench) -> Iterator[VirtualminAccount]:
    with hosted_account(lab_bench, DOMAIN) as hosted:
        yield hosted


def node_enabled(bench: Bench, account: VirtualminAccount) -> bool | None:
    return listing_enabled(bench.lab_of(account).domain_values(account.domain))


def test_a_health_check_from_the_server_page_reaches_the_node(lab_staff_page: Page, lab_bench: Bench) -> None:
    """The server calls the node itself: this is the click that fails on a runserver without the lab transport."""
    server = lab_bench.server("vm-a")
    VirtualminServer.objects.filter(pk=server.pk).update(
        health_check_error="stale error from an earlier run", last_health_check=timezone.now() - timedelta(hours=3)
    )
    page = lab_staff_page
    try:
        page.goto(f"{PLATFORM_BASE_URL}/provisioning/virtualmin/servers/{server.pk}/")
        expect(page.locator("#health-status")).to_contain_text("3 hours ago")
        page.get_by_role("button", name="Health Check").click()

        expect(page.locator("#health-status")).to_contain_text("Server is healthy and responding")
        server.refresh_from_db()
        assert server.health_check_error == ""
        assert timezone.now() - server.last_health_check < timedelta(minutes=2)
        assert server.is_healthy
    finally:
        lab_bench.refresh_health()  # later tests place accounts on this server


def test_the_account_page_shows_the_account_the_node_hosts(
    lab_staff_page: Page, lab_bench: Bench, account: VirtualminAccount
) -> None:
    page = lab_staff_page

    page.goto(account_url(account.pk))

    expect(page.locator("main h1")).to_contain_text(DOMAIN)
    expect(page.get_by_text("Active", exact=True).first).to_be_visible()
    expect(page.get_by_role("button", name="Suspend", exact=True)).to_be_visible()
    expect(page.get_by_role("link", name="Backup Now")).to_be_visible()
    assert lab_bench.lab_of(account).domain_exists(DOMAIN)
    assert node_enabled(lab_bench, account) is True


def test_suspend_then_activate_change_the_page_and_the_node(
    lab_staff_page: Page, lab_bench: Bench, account: VirtualminAccount
) -> None:
    page = lab_staff_page
    page.goto(account_url(account.pk))

    # Suspend: the confirm dialog, the queued message, then the worker's reconcile disables the domain.
    asked = click_and_confirm(page, page.get_by_role("button", name="Suspend", exact=True).click)
    assert "suspend this account" in asked
    expect(page.locator("#toast-container")).to_contain_text("is queued; its service is suspended.")
    reload_until_text(page, "main h1 + div", "Suspended", timeout=JOB_TIMEOUT_S, what=f"{DOMAIN} to read Suspended")
    expect(page.get_by_role("button", name="Activate", exact=True)).to_be_visible()
    until(lambda: node_enabled(lab_bench, account) is False, timeout=60, what="the node to disable the domain")

    # Activate: the same two halves in the other direction.
    asked = click_and_confirm(page, page.get_by_role("button", name="Activate", exact=True).click)
    assert "activate this account" in asked
    expect(page.locator("#toast-container")).to_contain_text("Activation of")
    reload_until_text(page, "main h1 + div", "Active", timeout=JOB_TIMEOUT_S, what=f"{DOMAIN} to read Active again")
    expect(page.get_by_role("button", name="Suspend", exact=True)).to_be_visible()
    until(lambda: node_enabled(lab_bench, account) is True, timeout=60, what="the node to enable the domain")
    account.refresh_from_db()
    assert account.status == "active"
