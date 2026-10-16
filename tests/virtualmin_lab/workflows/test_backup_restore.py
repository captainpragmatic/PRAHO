"""Workflow: full and config-only backups and restores, queued and run the way a Django-Q worker runs them.

`virtualmin_lab_roundtrip` already proves the data survives the CLI path (backup, delete, restore, forced
restore). This file proves the same operations through the job layer a staff action uses: admission writes a
pending job and queues a task, the task runs the backup or restore, and PRAHO's rows, the audit trail, the
object store and the node all agree on the outcome.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest

from apps.provisioning.virtualmin_backup_service import BackupConfig, VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

DOMAIN = "wfbackup.example.com"


@pytest.fixture(scope="module")
def account(bench: Bench) -> Iterator[VirtualminAccount]:
    with bench.hosted(DOMAIN) as hosted:
        yield hosted


def test_full_backup_then_restore_onto_a_deleted_domain(bench: Bench, account: VirtualminAccount) -> None:
    lab = bench.lab_of(account)
    data = DomainData(lab, account)
    data.seed(secrets.token_hex(6))
    before = data.snapshot()

    job = bench.backup(account, BackupConfig())
    assert job.status == "completed", (job.status, job.status_message)
    backup_id = job.result["backup_id"]

    # PRAHO: the job, its audit trail, the manifest and the encrypted objects in the store.
    assert job.parameters["backup_type"] == "full"
    assert {"virtualmin_provisioning_job_running", "virtualmin_provisioning_job_completed"} <= set(
        bench.audit_actions(job)
    ), bench.audit_actions(job)
    service = VirtualminBackupService(account.server)
    manifest = service.read_manifest(backup_id).unwrap()
    assert (manifest["backup_type"], manifest["domain"]) == ("full", DOMAIN)
    client, bucket = service._get_s3_client(), service._get_backup_bucket()
    for name in ("backup.tar.gz", "metadata.json"):
        head = client.head_object(Bucket=bucket, Key=f"virtualmin-backups/{backup_id}/{name}")
        assert head["ServerSideEncryption"] == "AES256", name
    # The node: nothing is left in the staging directory once the archive is published.
    assert bench.staged(account) == []

    # Disaster: the domain is gone from the node while PRAHO still lists the account.
    data.damage()
    lab.remove_domain(DOMAIN)
    assert not lab.domain_exists(DOMAIN)

    restore = bench.restore(account, backup_id)
    assert restore.status == "completed", (restore.status, restore.status_message)
    assert "virtualmin_provisioning_job_completed" in bench.audit_actions(restore)
    assert lab.domain_exists(DOMAIN)
    assert DomainData(lab, account).snapshot() == before, "files and rows come back exactly as they were backed up"
    account.refresh_from_db()
    assert account.status == "active"
    assert bench.staged(account) == []


def test_config_only_backup_restores_the_configuration_and_leaves_the_data(
    bench: Bench, account: VirtualminAccount
) -> None:
    """A config-only archive holds the domain's configuration and home structure, not its databases."""
    lab = bench.lab_of(account)
    data = DomainData(lab, account)
    data.seed(secrets.token_hex(6))
    rows_at_backup = data.sql(f"SELECT id, body FROM {data.TABLE} ORDER BY id")  # noqa: S608
    lab.quiet("modify-domain", {"domain": DOMAIN, "desc": "config at backup"})

    job = bench.backup(account, BackupConfig(backup_type="config_only"))
    assert job.status == "completed", (job.status, job.status_message)
    manifest = VirtualminBackupService(account.server).read_manifest(job.result["backup_id"]).unwrap()
    assert manifest["backup_type"] == "config_only"
    assert bench.staged(account) == []

    lab.quiet("modify-domain", {"domain": DOMAIN, "desc": "config after backup"})
    data.sql(f"DELETE FROM {data.TABLE} WHERE id = 1")  # noqa: S608
    rows_after_damage = data.sql(f"SELECT id, body FROM {data.TABLE} ORDER BY id")  # noqa: S608
    assert rows_after_damage != rows_at_backup

    restore = bench.restore(account, job.result["backup_id"], force=True)
    assert restore.status == "completed", (restore.status, restore.status_message)
    # The configuration came back; the database was never in the archive, so it is exactly as damaged.
    assert lab.domain_values(DOMAIN)["description"] == ["config at backup"]
    assert data.sql(f"SELECT id, body FROM {data.TABLE} ORDER BY id") == rows_after_damage  # noqa: S608
    # The forced restore took the safety backup of the live domain first.
    safety = bench.jobs(account, "backup_domain")[-1]
    assert safety.status == "completed"


def test_restoring_a_backup_that_does_not_exist_fails_and_touches_nothing(
    bench: Bench, account: VirtualminAccount
) -> None:
    lab = bench.lab_of(account)
    data = DomainData(lab, account)
    data.seed(secrets.token_hex(6))
    before = data.snapshot()

    restore = bench.restore(account, "does-not-exist", force=True)

    assert restore.status == "failed", (restore.status, restore.status_message)
    assert restore.status_message
    assert "virtualmin_provisioning_job_failed" in bench.audit_actions(restore)
    assert lab.domain_exists(DOMAIN)
    assert data.snapshot() == before
    account.refresh_from_db()
    assert account.status == "active"
    # A failed restore releases the account: the next admission is not blocked by it.
    management = VirtualminBackupManagementService(account.server)
    assert management.create_backup_job(account, BackupConfig(backup_type="config_only")).is_ok()
    bench.clear_queue()
    VirtualminProvisioningJob.objects.filter(account=account, status="pending").update(  # fsm-bypass: lab cleanup
        status="failed"
    )
