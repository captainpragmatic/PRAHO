"""Workflow: PRAHO's views of a node converge on the node's truth, and the Service's truth converges on the node.

- `sync_virtualmin_usage` reads usage from the node into the account row.
- The server health and statistics tasks stamp the server from what the node answers.
- The divergence backstop finds a Service and an account that disagree (a lost reconcile enqueue) and the
  reconciler it queues repairs the node. The backstop looks at PRAHO's rows only: a domain someone changes on
  the node behind PRAHO's back is not a signature it detects, and this file does not pretend otherwise.

The lab nodes have no filesystem quotas and print no usage fields (README, Limits), so the usage sync can only be
shown to run cleanly against a node and stamp the account; the usage values it reads are always 0 here and are
not asserted.
"""

from __future__ import annotations

import io
from collections.abc import Iterator

import pytest
from django.core.cache import cache
from django.core.management import call_command
from django.utils import timezone

from apps.provisioning.models import Service
from apps.provisioning.virtualmin_gateway import listing_enabled
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_tasks import (
    health_check_virtualmin_servers,
    reconcile_divergent_services_task,
    update_virtualmin_server_statistics,
)
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

DOMAIN = "wfsync.example.com"


@pytest.fixture(scope="module")
def account(bench: Bench) -> Iterator[VirtualminAccount]:
    with bench.hosted(DOMAIN) as hosted:
        yield hosted


def test_usage_sync_runs_against_the_node_and_stamps_the_account(bench: Bench, account: VirtualminAccount) -> None:
    DomainData(bench.lab_of(account), account).write("big.bin", "x" * 4096)
    VirtualminAccount.objects.filter(pk=account.pk).update(last_sync_at=None)
    out = io.StringIO()

    call_command("sync_virtualmin_usage", "--server", account.server.name, stdout=out)

    assert "0 errors" in out.getvalue(), out.getvalue()
    account.refresh_from_db()
    assert account.last_sync_at is not None
    assert (timezone.now() - account.last_sync_at).total_seconds() < 600
    assert account.current_disk_usage_mb >= 0 and account.current_bandwidth_usage_mb >= 0
    other = VirtualminAccount.objects.exclude(server=account.server).first()
    assert other is None or other.last_sync_at is None or other.last_sync_at < account.last_sync_at, (
        "--server limits the sync to that node's accounts"
    )


def test_health_and_statistics_tasks_stamp_the_servers_from_the_nodes(bench: Bench, account: VirtualminAccount) -> None:
    server = bench.server("vm-a")
    server.last_health_check = None
    server.current_domains = 0
    server.save(update_fields=["last_health_check", "current_domains", "updated_at"])
    cache.delete("virtualmin_health_check_lock")
    cache.delete("virtualmin_stats_update_lock")

    health = health_check_virtualmin_servers()
    stats = update_virtualmin_server_statistics()

    assert health["success"] and health["results"]["healthy_servers"] == 2, health
    assert stats["success"] and stats["results"]["updated_servers"] == 2, stats
    server = bench.server("vm-a")  # read again: the tasks wrote it
    assert server.is_healthy and server.last_health_check is not None
    assert server.current_domains == len(bench.lab("vm-a").domain_names()), "the count is the node's own listing"


def test_divergence_backstop_repairs_a_lost_suspension_and_a_lost_activation(
    bench: Bench, account: VirtualminAccount
) -> None:
    lab = bench.lab_of(account)
    service = Service.objects.get(pk=account.service_id)
    bench.clear_queue()

    # The Service was suspended but the reconcile enqueue was lost: no signal ran, the account is still live.
    Service.objects.filter(pk=service.pk).update(  # fsm-bypass: the state a lost enqueue leaves behind
        status="suspended", suspension_reason="payment_overdue"
    )
    assert listing_enabled(lab.domain_values(DOMAIN)) is True
    swept = reconcile_divergent_services_task()
    assert swept["success"] and swept["queued"] >= 1, swept
    runs = bench.run_queue()
    assert [run.error for run in runs if run.error] == []
    account.refresh_from_db()
    assert account.status == "suspended"
    assert listing_enabled(lab.domain_values(DOMAIN)) is False
    assert [job.status for job in bench.jobs(account, "suspend_domain")] == ["completed"]

    # The reverse: the Service is active again but the account was left suspended.
    Service.objects.filter(pk=service.pk).update(  # fsm-bypass: the state a lost enqueue leaves behind
        status="active", suspension_reason=""
    )
    swept = reconcile_divergent_services_task()
    assert swept["success"] and swept["queued"] >= 1, swept
    runs = bench.run_queue()
    assert [run.error for run in runs if run.error] == []
    account.refresh_from_db()
    assert account.status == "active"
    assert listing_enabled(lab.domain_values(DOMAIN)) is True
    assert [job.status for job in bench.jobs(account, "unsuspend_domain")] == ["completed"]

    # Converged: a further sweep has nothing to queue for this account.
    swept = reconcile_divergent_services_task()
    bench.run_queue()
    account.refresh_from_db()
    assert account.status == "active" and listing_enabled(lab.domain_values(DOMAIN)) is True
