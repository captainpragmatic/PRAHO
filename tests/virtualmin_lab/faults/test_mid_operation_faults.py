"""Faults in the middle of a backup and of a restore: Webmin stopped, the network cut.

The call that was in flight has no answer: the node may have done the work, part of it, or none. PRAHO must
say exactly that and nothing more:

- a backup that gets no answer fails, once, and publishes nothing (a standalone backup changes nothing it could
  leave half done, so it is not parked);
- a restore that gets no answer is parked for an operator (`attention`): it may have overwritten the domain. It
  keeps the account's exclusion, so nothing else can write the domain, the reconciler yields, and it never reads
  as completed;
- neither is sent twice.

Every test provisions its own account, so a fault cannot spoil the next one.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Any

import pytest

from apps.provisioning.models import Service
from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.provisioning.virtualmin_tasks import reconcile_virtualmin_service_state
from tests.virtualmin_lab.faults.harness import (
    Chaos,
    backup_objects,
    count_attempts,
    exclusion_holds,
    resolve_as_operator,
)
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

# Long enough for a lost answer to show as a timeout, short enough for a test.
CALL_TIMEOUT_SECONDS = 30
BLOB_MB = 150
# The restore-domain call starts about a second after the archive lands; this puts the fault inside it.
RESTORE_FAULT_DELAY = 4.0


@pytest.fixture(autouse=True)
def short_command_timeout(bench: Bench) -> None:
    bench.set_setting("provisioning.migration_backup_timeout_seconds", CALL_TIMEOUT_SECONDS)


def _assert_backup_failed_once_and_published_nothing(
    bench: Bench, account: VirtualminAccount, job: VirtualminProvisioningJob, attempts: Any, before: set[str]
) -> None:
    assert job.status == "failed", (job.status, job.status_message)
    assert job.status_message
    assert job.result["retriability"] == "unknown", "an unanswered command is never reported as a definite failure"
    assert attempts["backup-domain"] == 1, "a command that may have run is never sent twice"
    actions = bench.audit_actions(job)
    assert "virtualmin_provisioning_job_failed" in actions and "virtualmin_provisioning_job_completed" not in actions
    assert backup_objects(account.server) == before, "no archive and no manifest was published for it"
    assert not exclusion_holds(account), "a standalone backup that never answered releases the account"


def _assert_restore_parked(
    bench: Bench, account: VirtualminAccount, job: VirtualminProvisioningJob, attempts: Any
) -> None:
    assert job.status == "attention", (job.status, job.status_message)
    assert job.result["retriability"] == "unknown"
    assert attempts["restore-domain"] == 1, "the destructive call was sent once and never replayed"
    actions = bench.audit_actions(job)
    assert "virtualmin_provisioning_job_attention" in actions
    assert "virtualmin_provisioning_job_completed" not in actions, "nothing is reported done"

    # The exclusion holds: no other operation may write the domain while its fate is unknown.
    assert exclusion_holds(account)
    management = VirtualminBackupManagementService(account.server)
    for refusal in (
        management.create_backup_job(account, BackupConfig()),
        management.create_restore_job(account, RestoreConfig(backup_id="any", force_restore=True)),
        VirtualminMigrationService().start_migration(
            account, bench.server("vm-b"), initiated_by=None, reason="manual"
        ),
    ):
        assert refusal.is_err() and "active" in refusal.unwrap_err(), refusal
    # The reconciler yields to it (ADR-0051): a Service change cannot enable or disable the domain meanwhile.
    Service.objects.filter(pk=account.service_id).update(  # fsm-bypass: a lost-enqueue state, no signal
        status="suspended", suspension_reason="payment_overdue"
    )
    assert reconcile_virtualmin_service_state(str(account.service_id))["action"] == "operation_active"
    Service.objects.filter(pk=account.service_id).update(status="active", suspension_reason="")
    # The pushed archive stays on the node as the operator's reconciliation artifact.
    assert bench.staged(account), "an uncertain restore keeps its archive"

    # The operator resolves it, and the account is free again.
    resolve_as_operator(job, "workflow")
    assert not exclusion_holds(account)
    assert management.create_backup_job(account, BackupConfig(backup_type="config_only")).is_ok()


def _backup_under_fault(bench: Bench, chaos: Chaos, domain: str, fault: Callable[[], None]) -> None:
    with bench.hosted(domain) as account:
        lab = bench.lab_of(account)
        data = DomainData(lab, account)
        data.seed(secrets.token_hex(6))
        data.add_blob(BLOB_MB)
        before_data, before_objects = data.snapshot(), backup_objects(account.server)
        with count_attempts() as attempts, chaos.during(chaos.staging_has_archive("vm-a"), fault, delay=1.0):
            job = bench.backup(account)
        chaos.mend()
        _assert_backup_failed_once_and_published_nothing(bench, account, job, attempts, before_objects)
        assert data.snapshot() == before_data, "a backup never changes the domain"
        chaos.remove_staged("vm-a")


def _restore_under_fault(bench: Bench, chaos: Chaos, domain: str, fault: Callable[[], None]) -> None:
    with bench.hosted(domain) as account:
        lab = bench.lab_of(account)
        DomainData(lab, account).seed(secrets.token_hex(6))
        backup = bench.backup(account)
        assert backup.status == "completed", (backup.status, backup.status_message)
        lab.remove_domain(domain)  # the node lost it; the restore is the recovery
        bench.clear_queue()
        admitted = VirtualminBackupManagementService(account.server).create_restore_job(
            account, RestoreConfig(backup_id=backup.result["backup_id"]), initiated_by="workflow"
        )
        assert admitted.is_ok(), admitted
        job = admitted.unwrap()
        with count_attempts() as attempts, chaos.during(
            chaos.staging_has_archive("vm-a"), fault, delay=RESTORE_FAULT_DELAY
        ):
            bench.run_one("run_virtualmin_restore")
        job.refresh_from_db()
        chaos.mend()
        _assert_restore_parked(bench, account, job, attempts)
        chaos.remove_staged("vm-a")


def test_webmin_stopped_during_a_backup(bench: Bench, chaos: Chaos) -> None:
    _backup_under_fault(bench, chaos, "wffaulta.example.com", lambda: chaos.stop_webmin("vm-a"))


def test_network_cut_during_a_backup(bench: Bench, chaos: Chaos) -> None:
    _backup_under_fault(bench, chaos, "wffaultb.example.com", lambda: chaos.disconnect("vm-a"))


def test_webmin_stopped_during_a_restore(bench: Bench, chaos: Chaos) -> None:
    _restore_under_fault(bench, chaos, "wffaultc.example.com", lambda: chaos.stop_webmin("vm-a"))


def test_network_cut_during_a_restore(bench: Bench, chaos: Chaos) -> None:
    _restore_under_fault(bench, chaos, "wffaultd.example.com", lambda: chaos.disconnect("vm-a"))
