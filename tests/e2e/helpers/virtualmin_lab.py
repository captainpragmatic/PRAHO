"""Access to the Docker Virtualmin lab for the browser smoke tests (`make test-virtualmin-e2e`).

The tests drive Platform's staff pages in a real browser and then ask the node what happened, so every check
has two halves: the page (badges, messages, buttons) and the node (`list-domains` through the lab helper).
Django is set up by `tests/e2e/platform/conftest.py` when the runner sets `VIRTUALMIN_E2E=1`; nothing here
imports a model at module level, so importing this module is safe in any e2e run.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from playwright.sync_api import Page

from tests.e2e.helpers.constants import PLATFORM_BASE_URL, PROJECT_ROOT
from tests.e2e.helpers.htmx import wait_for_htmx_settle

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_models import VirtualminAccount
    from tests.virtualmin_lab.workflows.harness import Bench

STAFF_ENV = PROJECT_ROOT / "deploy" / "virtualmin-lab" / ".state" / "staff.env"
# A provisioning chain (reconcile, create-domain, the node's own work) takes tens of seconds; a backup of a
# small domain a few; a migration a minute or two. These are ceilings, not sleeps: every wait polls.
PROVISION_TIMEOUT_S = 240
JOB_TIMEOUT_S = 300
MIGRATION_TIMEOUT_S = 480
RELOAD_INTERVAL_S = 2.0


def staff_credentials() -> tuple[str, str]:
    """The lab staff login `virtualmin_lab_bootstrap` wrote into the git-ignored lab state."""
    assert STAFF_ENV.is_file(), f"{STAFF_ENV} is missing; run: make virtualmin-lab-up"
    values = dict(line.split("=", 1) for line in STAFF_ENV.read_text().splitlines() if "=" in line)
    return values["LAB_STAFF_EMAIL"], values["LAB_STAFF_PASSWORD"]


def eventually[T](check: Callable[[], T | None], *, timeout: float, what: str, interval: float = 1.0) -> T:
    """Poll `check` until it returns something other than None/False; fail with `what` when time runs out.

    For state that lives outside the page (a row, the node). Anything the page itself shows is waited for
    with a retrying `expect`, never with this and never with a fixed sleep.
    """
    deadline = time.monotonic() + timeout
    while True:
        value = check()
        if value is not None and value is not False:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what}")
        time.sleep(interval)


def until(predicate: Callable[[], bool], *, timeout: float, what: str, interval: float = 1.0) -> None:
    """`eventually` for a yes/no question about state outside the page."""
    eventually(lambda: True if predicate() else None, timeout=timeout, what=what, interval=interval)


def accept_next_dialog(page: Page) -> list[str]:
    """Accept the next native confirm() (hx-confirm) and return the list its message is appended to."""
    messages: list[str] = []
    page.once("dialog", lambda dialog: (messages.append(dialog.message), dialog.accept()))
    return messages


def click_and_confirm(page: Page, locator_click: Callable[[], None]) -> str:
    """Click through an hx-confirm dialog, wait for the HTMX request it started, return the confirm text."""
    messages = accept_next_dialog(page)
    locator_click()
    wait_for_htmx_settle(page)
    assert messages, "the action asked for no confirmation"
    return messages[0]


def account_url(account_id: object) -> str:
    return f"{PLATFORM_BASE_URL}/provisioning/virtualmin/accounts/{account_id}/"


def job_url(job_id: object) -> str:
    return f"{PLATFORM_BASE_URL}/provisioning/virtualmin/jobs/{job_id}/status/"


def reload_until_text(page: Page, selector: str, text: str, *, timeout: float, what: str) -> None:
    """Reload the page until `selector` contains `text` (a page that does not poll itself, such as an account page)."""
    deadline = time.monotonic() + timeout
    while True:
        if text in (page.locator(selector).first.inner_text() if page.locator(selector).count() else ""):
            return
        if time.monotonic() >= deadline:
            body = page.locator("main").first.inner_text()[:600]
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what}; the page says: {body!r}")
        time.sleep(RELOAD_INTERVAL_S)
        page.reload()
        page.wait_for_load_state("domcontentloaded")


@contextmanager
def hosted_account(bench: Bench, domain: str, *, node: str = "vm-a") -> Iterator[VirtualminAccount]:
    """An active Service for `domain`, taken to a hosted account by PRAHO's own signal, reconcile and task.

    The server's worker thread runs the chain (the test process must not drain the queue), so this creates the
    Service and waits for the account to be active and the domain to be on the node. The account and the domain
    are removed afterwards, whatever the test did.
    """
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

    bench.forget(domain)
    bench.prefer(node)
    service = bench.new_service(domain)
    try:
        account = eventually(
            lambda: VirtualminAccount.objects.filter(service=service, status="active").first(),
            timeout=PROVISION_TIMEOUT_S,
            what=f"{domain} to be provisioned as an active account",
        )
        eventually(
            lambda: bench.lab_of(account).domain_exists(domain),
            timeout=60,
            what=f"{domain} to be on its node",
        )
        yield account
    finally:
        bench.forget(domain)


JOB_STATUS = "dt:text-is('Status') + dd"
JOB_IN_FLIGHT = ("Pending", "Running")


def job_id_from(page: Page) -> str:
    """The job on screen: from the URL after a redirect, else from the log pane of a job page swapped in by HTMX.

    An hx-post that redirects swaps the job page into the body but leaves the address bar on the page the
    click came from, so the job's own log URL (`.../jobs/<id>/logs/`) is the reliable source.
    """
    parts = page.url.rstrip("/").split("/")
    if parts[-1] == "status" and parts[-3] == "jobs":
        return parts[-2]
    logs_url = page.locator("button[hx-get$='/logs/']").first.get_attribute("hx-get") or ""
    match = re.search(r"/jobs/([0-9a-f-]{36})/logs/", logs_url)
    assert match, f"no job page on screen at {page.url}"
    return match.group(1)


def wait_for_job(page: Page, *, timeout: float = JOB_TIMEOUT_S, final: str = "Completed") -> str:
    """Reload a job page until its status badge reads `final`; fail at once on any other settled status.

    The status badge is rendered once per page load (only the log pane polls), so the page is reloaded.
    A Failed job fails the test immediately with the page's own error text instead of after the timeout.
    """
    deadline = time.monotonic() + timeout
    while True:
        status = page.locator(JOB_STATUS).first.inner_text().strip()
        if status == final:
            return status
        if status not in JOB_IN_FLIGHT:
            detail = page.locator("main").first.inner_text()[:800]
            raise AssertionError(f"the job settled as {status!r}, not {final!r}: {detail!r}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"the job was still {status!r} after {timeout:.0f}s")
        time.sleep(RELOAD_INTERVAL_S)
        page.reload()
        page.wait_for_load_state("domcontentloaded")
