"""Workflow: disaster recovery. What it can honestly report, what it refuses, and the recovery that exists today.

PRAHO as the source of truth (docs/domain, ADR-0061 phase 0): the integrity report says whether every account
could be rebuilt from PRAHO's rows, and the legacy rebuild produces a plan but refuses to run, because it would
recreate empty domains and lose the customers' data. The recovery that exists today is a restore from a backup:
onto the same node when the domain is lost, or onto another node. Recovery to a replacement node that also
repoints the account is the ADR-0061 phase 2 service and does not exist yet.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest

from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

DOMAIN = "wfrecover.example.com"


@pytest.fixture(scope="module")
def account(bench: Bench) -> Iterator[VirtualminAccount]:
    with bench.hosted(DOMAIN) as hosted:
        yield hosted


def test_integrity_report_matches_what_the_rows_support(bench: Bench, account: VirtualminAccount) -> None:
    report = VirtualminDisasterRecoveryService().verify_praho_data_integrity().unwrap()

    flagged = {domain for issue in report["missing_data_issues"] for domain in issue.get("domains", [])}
    seedless = set(
        VirtualminAccount.objects.filter(praho_service_id__isnull=True).values_list("domain", flat=True)
    ) | set(VirtualminAccount.objects.filter(praho_customer_id__isnull=True).values_list("domain", flat=True))
    assert DOMAIN not in flagged, "an account provisioned by the pipeline carries its recovery seed"
    assert seedless <= flagged, "every account without a recovery seed is reported"
    assert report["total_accounts"] == VirtualminAccount.objects.count()
    assert report["disaster_recovery_ready"] is (not report["missing_data_issues"] and (
        report["recoverable_accounts"] == report["total_accounts"]
    )), "readiness is never claimed beside an issue"
    assert not [issue for issue in report["missing_data_issues"] if issue["issue"] == "servers_without_usable_credentials"]
    assert report["transport_warnings"] == [], "both lab servers have a managed deployment"


def test_recovery_capability_plans_for_the_node_and_the_rebuild_refuses_to_run(
    bench: Bench, account: VirtualminAccount
) -> None:
    server = bench.server("vm-a")
    service = VirtualminDisasterRecoveryService()
    domains_on_node = bench.lab("vm-a").domain_names()
    rows_before = list(VirtualminAccount.objects.order_by("pk").values_list("pk", "status", "server_id"))

    capability = service.test_recovery_capability(server).unwrap()
    assert capability["recovery_ready"] is True and capability["connection_status"] == "healthy"
    planned = {item["domain"] for item in capability["rebuild_plan"]}
    live = set(
        VirtualminAccount.objects.filter(server=server, status__in=("active", "suspended")).values_list(
            "domain", flat=True
        )
    )
    assert planned == live and DOMAIN in planned
    assert "data-presence check only" in capability["message"]

    plan = service.rebuild_server_from_praho(server, dry_run=True).unwrap()
    assert plan["dry_run"] is True and plan["accounts_to_rebuild"] == len(live)

    refused = service.rebuild_server_from_praho(server, dry_run=False)
    assert refused.is_err() and "only a dry run is available" in refused.unwrap_err()
    # Planning and refusing touched neither side.
    assert bench.lab("vm-a").domain_names() == domains_on_node
    assert list(VirtualminAccount.objects.order_by("pk").values_list("pk", "status", "server_id")) == rows_before


def test_recovery_from_a_backup_onto_a_replacement_node(bench: Bench, account: VirtualminAccount) -> None:
    """The node lost the domain: the backup in the object store brings it back on another node, data included."""
    source, replacement = bench.lab("vm-a"), bench.lab("vm-b")
    data = DomainData(source, account)
    data.seed(secrets.token_hex(6))
    before = data.snapshot()
    backup = bench.backup(account, BackupConfig())
    assert backup.status == "completed", (backup.status, backup.status_message)

    source.remove_domain(DOMAIN)  # the node and its disks are gone
    assert not source.domain_exists(DOMAIN)
    bench.clear_queue()
    admitted = VirtualminBackupManagementService(account.server).create_restore_job(
        account,
        RestoreConfig(backup_id=backup.result["backup_id"]),
        target_server=bench.server("vm-b"),
        initiated_by="workflow",
    )
    assert admitted.is_ok(), admitted
    restore = admitted.unwrap()
    assert restore.server_id == bench.server("vm-b").pk, "the job runs against the replacement node"
    bench.run_one("run_virtualmin_restore")
    restore.refresh_from_db()

    assert restore.status == "completed", (restore.status, restore.status_message)
    assert "virtualmin_provisioning_job_completed" in bench.audit_actions(restore)
    assert replacement.domain_exists(DOMAIN)
    assert DomainData(replacement, account).snapshot() == before, "files and rows are on the replacement node"
    assert not source.domain_exists(DOMAIN), "the lost node was not touched"
    replacement.remove_domain(DOMAIN)
