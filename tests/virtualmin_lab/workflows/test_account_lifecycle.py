"""Workflow: a hosting account from provisioning to deletion, through PRAHO's Service, signals and tasks.

Provision (a Service becomes active, the signal queues a reconcile, the reconcile queues provisioning),
suspend and activate through the Service (ADR-0051), a plan change, the deletion protection toggle, and
delete. Each step asserts PRAHO (rows, jobs, audit events) and the node (`list-domains`, content).

The contract suite proves what each Virtualmin program answers; `virtualmin_lab_checks` check 1 proves the
create-domain parameters and the retry. This file proves the workflows built on them.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.core.management import call_command

from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.services import STAFF_ACCOUNT_SUSPENSION_REASON, HostingAccountStaffActions
from apps.provisioning.virtualmin_gateway import listing_enabled
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from tests.virtualmin_lab.contract.harness import Lab
from tests.virtualmin_lab.workflows.harness import Bench

DOMAIN = "wflife.example.com"


@dataclass
class Hosted:
    bench: Bench
    account: VirtualminAccount

    @property
    def lab(self) -> Lab:
        return self.bench.lab_of(self.account)

    @property
    def service(self) -> Service:
        return Service.objects.get(pk=self.account.service_id)

    def node_enabled(self) -> bool | None:
        return listing_enabled(self.lab.domain_values(DOMAIN))

    def refresh(self) -> VirtualminAccount:
        self.account.refresh_from_db()
        return self.account


@pytest.fixture(scope="module")
def hosted(bench: Bench) -> Iterator[Hosted]:
    """The account every step of the lifecycle works on, provisioned once through the real pipeline.

    vm-a is the preferred node, so the account starts where the migration workflow expects its source.
    """
    with bench.hosted(DOMAIN) as account:
        yield Hosted(bench, account)


def test_provisioning_creates_the_hosted_account(hosted: Hosted) -> None:
    account, lab = hosted.refresh(), hosted.lab
    # PRAHO
    assert (account.status, account.protected_from_deletion) == ("active", True)
    assert hosted.service.status == "active"
    assert hosted.bench.key_of(account.server) == "vm-a", "placement follows the server weight"
    [job] = hosted.bench.jobs(account, "create_domain")
    assert job.status == "completed", (job.status, job.status_message)
    actions = hosted.bench.audit_actions(account)
    assert "virtualmin_account_created" in actions, actions
    assert "virtualmin_provisioning_job_completed" in hosted.bench.audit_actions(job)
    # The node
    assert lab.domain_exists(DOMAIN)
    assert hosted.node_enabled() is True
    lab.exec("test", "-d", f"/home/{account.virtualmin_username}/public_html")
    assert hosted.bench.server("vm-a").current_domains >= 1


def test_staff_suspend_then_activate_go_through_the_service(hosted: Hosted) -> None:
    bench, account = hosted.bench, hosted.refresh()
    bench.clear_queue()

    # Suspend: the Service changes, the reconcile queued by its signal changes the node. Staff never call Virtualmin.
    suspended = HostingAccountStaffActions.suspend(account)
    assert suspended.is_ok(), suspended
    service = hosted.service
    assert (service.status, service.suspension_reason) == ("suspended", STAFF_ACCOUNT_SUSPENSION_REASON)
    assert hosted.node_enabled() is True, "nothing reaches the node before the reconcile runs"
    runs = bench.run_queue()
    assert [run.name for run in runs if run.error] == [], runs
    assert "reconcile_virtualmin_service_state" in [run.name for run in runs]
    assert hosted.refresh().status == "suspended"
    assert hosted.node_enabled() is False
    [suspend_job] = bench.jobs(account, "suspend_domain")
    assert suspend_job.status == "completed", (suspend_job.status, suspend_job.status_message)
    assert "virtualmin_provisioning_job_completed" in bench.audit_actions(suspend_job)

    # Activate lifts the staff token and the reconcile turns the domain back on.
    resumed = HostingAccountStaffActions.activate(hosted.refresh())
    assert resumed.is_ok(), resumed
    assert hosted.service.status == "active"
    assert hosted.node_enabled() is False, "nothing reaches the node before the reconcile runs"
    runs = bench.run_queue()
    assert [run.name for run in runs if run.error] == [], runs
    assert hosted.refresh().status == "active"
    assert hosted.node_enabled() is True
    [unsuspend_job] = bench.jobs(account, "unsuspend_domain")
    assert unsuspend_job.status == "completed", (unsuspend_job.status, unsuspend_job.status_message)


def test_changing_the_plan_leaves_the_domain_alone(hosted: Hosted) -> None:
    """A plan change is a Service edit; no PRAHO path pushes quotas to the node (see the report).

    The staff service form saves `service_plan` and nothing more, and "Unsupported automated plan changes
    remain unavailable" (docs/domain/CUSTOMER_RECOVERY_AND_SERVICE_REQUESTS.md). What the workflow has to
    guarantee is that the edit does not disturb hosting: the reconcile it triggers finds nothing to change,
    and the node keeps the quotas the account was created with.
    """
    bench, account = hosted.bench, hosted.refresh()
    quota_before = hosted.lab.domain_values(DOMAIN)
    plan = ServicePlan.objects.create(
        name="Virtualmin lab hosting plus", plan_type="shared_hosting", is_active=True, price_monthly=Decimal("0.00")
    )
    try:
        bench.clear_queue()
        service = hosted.service
        service.service_plan = plan
        service.save()  # what the staff service form does
        runs = bench.run_queue()
        assert [run.name for run in runs] == ["reconcile_virtualmin_service_state"], runs
        assert runs[0].result["action"] == "noop", runs[0].result
        assert not bench.jobs(account, "modify_domain"), "no modify-domain job exists for a plan change"
        assert hosted.node_enabled() is True
        assert hosted.lab.domain_values(DOMAIN) == quota_before
    finally:
        service = hosted.service
        service.service_plan = ServicePlan.objects.get(name="Virtualmin lab hosting")
        service.save()
        bench.run_queue()
        plan.delete()


def test_deletion_protection_toggle_decides_whether_delete_is_allowed(hosted: Hosted) -> None:
    bench, account = hosted.bench, hosted.refresh()
    assert account.protected_from_deletion is True
    out = io.StringIO()
    call_command("virtualmin_protection", "--status", stdout=out)
    status_line = next(line for line in out.getvalue().splitlines() if DOMAIN in line)
    assert "PROTECTED" in status_line and "UNPROTECTED" not in status_line, status_line

    # Protected: refused before any call to the node, whatever the account's state.
    refused = VirtualminProvisioningService(account.server).delete_account(account)
    assert refused.is_err() and "protected from deletion" in refused.unwrap_err()
    assert hosted.lab.domain_exists(DOMAIN)
    assert not bench.jobs(account, "delete_domain")

    # Unprotected but healthy: still refused. Only a terminated or errored account is deleted.
    with patch("builtins.input", return_value="I really am sure I want to do this!"):
        call_command("virtualmin_protection", "--disable", "--domain", DOMAIN, "--confirm", stdout=io.StringIO())
    assert hosted.refresh().protected_from_deletion is False
    refused = VirtualminProvisioningService(account.server).delete_account(hosted.refresh())
    assert refused.is_err() and "must be terminated or in error state" in refused.unwrap_err()
    assert hosted.lab.domain_exists(DOMAIN)

    call_command("virtualmin_protection", "--enable", "--domain", DOMAIN, stdout=io.StringIO())
    assert hosted.refresh().protected_from_deletion is True


def test_delete_removes_the_domain_from_the_node_and_terminates_the_account(hosted: Hosted) -> None:
    """The account a failed provisioning left in `error` is the one delete accepts, once unprotected."""
    from apps.provisioning.virtualmin_tasks import delete_virtualmin_account_async  # noqa: PLC0415

    bench, account = hosted.bench, hosted.refresh()
    VirtualminAccount.objects.filter(pk=account.pk).update(  # fsm-bypass: the state a failed provisioning leaves
        status="error", protected_from_deletion=False
    )
    domains_before = bench.server("vm-a").current_domains
    bench.clear_queue()
    delete_virtualmin_account_async(str(account.pk))
    runs = bench.run_queue()
    assert [run.error for run in runs] == [""], runs
    assert runs[0].result["success"] is True, runs[0].result

    assert hosted.refresh().status == "terminated"
    [job] = bench.jobs(account, "delete_domain")
    assert job.status == "completed", (job.status, job.status_message)
    assert "virtualmin_provisioning_job_completed" in bench.audit_actions(job)
    assert "virtualmin_account_status_changed" in bench.audit_actions(account)
    assert not hosted.lab.domain_exists(DOMAIN)
    assert bench.server("vm-a").current_domains == max(0, domains_before - 1)
