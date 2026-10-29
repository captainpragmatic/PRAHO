"""Workflow: PRAHO's views of a node converge on the node's truth, and the Service's truth converges on the node.

- The private collector measures files/DB independently and publishes through the hourly node task.
- The server health and statistics tasks stamp the server from what the node answers.
- The divergence backstop finds a Service and an account that disagree (a lost reconcile enqueue) and the
  reconciler it queues repairs the node. The backstop looks at PRAHO's rows only: a domain someone changes on
  the node behind PRAHO's back is not a signature it detects, and this file does not pretend otherwise.

The lab has no filesystem quotas. Allocated bytes and Apache response bytes do not depend on quotas.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.provisioning.models import Service
from apps.provisioning.virtualmin_gateway import listing_enabled
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_tasks import (
    health_check_virtualmin_servers,
    reconcile_divergent_services_task,
    update_virtualmin_server_statistics,
)
from apps.provisioning.virtualmin_usage_models import NodeUsageSyncState, UsageReading
from apps.provisioning.virtualmin_usage_service import public_usage
from apps.provisioning.virtualmin_usage_tasks import sync_node_usage, transport_identity
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

DOMAIN = "wfsync.example.com"


@pytest.fixture(scope="module")
def account(bench: Bench) -> Iterator[VirtualminAccount]:
    with bench.hosted(DOMAIN) as hosted:
        yield hosted


def test_usage_measures_independent_file_database_growth_and_real_http(bench: Bench, account: VirtualminAccount) -> None:
    lab = bench.lab_of(account)
    data = DomainData(lab, account)
    assets = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"
    lab.exec("install", "-d", "-m", "0700", "/var/lib/praho/usage", "/var/log/praho")
    lab.exec("install", "-d", "-m", "0755", "/usr/local/libexec")
    for name in ("praho_usage.py", "praho-usage-metadata.pl", "praho-usage-hook"):
        target = f"{lab.node.container}:/usr/local/libexec/{name}"
        subprocess.run(["docker", "cp", str(assets / name), target], check=True, capture_output=True, timeout=60)  # noqa: S603, S607  # Fixed lab container and repository asset.
        lab.exec("chmod", "0700", f"/usr/local/libexec/{name}")
    lab.exec("/usr/bin/python3", "/usr/local/libexec/praho_usage.py", "init")
    lab.exec("perl", "/usr/local/libexec/praho-usage-metadata.pl", "reconcile")

    def collect():
        lab.exec("/usr/bin/python3", "/usr/local/libexec/praho_usage.py", "refresh")
        token = uuid4()
        NodeUsageSyncState.objects.update_or_create(server=account.server, defaults={"token": token,
            "lease_until": timezone.now() + timedelta(seconds=330), "input_identity": transport_identity(account.server)})
        result = sync_node_usage(str(account.server_id), str(token))
        assert result["state"] in {"ok", "unassigned_accounts"}, result
        return UsageReading.objects.filter(account=account, disk_total_bytes__isnull=False).latest("taken_at")

    with patch("apps.provisioning.virtualmin_usage_service.enabled", return_value=True):
        first = collect()
        data.add_blob(50)
        second = collect()
        assert second.disk_files_bytes - first.disk_files_bytes >= 50 * 1024**2
        assert second.disk_db_bytes == first.disk_db_bytes
        data.sql("CREATE TABLE usage_growth (body LONGBLOB) ENGINE=MyISAM")
        try:
            data.sql("INSERT INTO usage_growth VALUES (REPEAT('u', 1048576))")
            third = collect()
            assert third.disk_db_bytes > second.disk_db_bytes + 1000000
            assert abs(third.disk_files_bytes - second.disk_files_bytes) < 1024**2
            account.refresh_from_db()
            account.service.refresh_from_db()
            assert account.current_disk_usage_mb == account.service.disk_usage_mb == third.disk_total_bytes // 1024**2
            assert public_usage(account.service)["disk_usage_gb"] > 0

            data.write("usage.txt", "usage body\n")
            for scheme, port in (("http", 80), ("https", 443)):
                code = lab.exec("curl", "-sk", "--resolve", f"{account.domain}:{port}:127.0.0.1", "-o", "/dev/null", "-w", "%{http_code}", f"{scheme}://{account.domain}/usage.txt")
                assert code == "200", (scheme, code)
            collect()
            exported = json.loads(lab.exec("sh", "-c", 'printf %s "{}" | /usr/bin/python3 /usr/local/libexec/praho_usage.py export'))
            row = next(row for row in exported["records"] if row["domain"] == account.domain)
            log = lab.exec("cat", "/var/log/praho/usage.log")
            own = [line.split() for line in log.splitlines() if line.split()[2] == row["domain_id"]]
            assert sum(int(line[4]) for line in own) >= len("usage body\n") * 2
            assert "password_for_mysql" not in json.dumps(exported)
            assert set(row) <= {"domain", "domain_id", "username", "scan_started_at", "scan_finished_at", "mailboxes", "databases", "disk_files_bytes", "disk_db_bytes", "disk_total_bytes", "segments", "binding_verified", "binding_started_at", "present"}
        finally:
            data.sql("DROP TABLE usage_growth")
            data.remove("blob.bin")


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
