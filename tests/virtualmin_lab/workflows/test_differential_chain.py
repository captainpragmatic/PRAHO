"""Workflow: a differential chain with the flag on (ADR-0059): base, differential, pair restore.

`virtualmin_lab_checks` checks 4b to 4e prove the node-side step, the chain state through the service entry
points, the schedule and the pair restore's write barrier. This file runs the chain the way staff do, through
queued jobs, and asserts what PRAHO records at each link: the account's chain fields, the manifests' lineage,
the audit trail, the data the pair brings back and the end of the chain.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest

from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_gateway import listing_enabled
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

DOMAIN = "wfchain.example.com"


@pytest.fixture(scope="module")
def account(bench: Bench) -> Iterator[VirtualminAccount]:
    with bench.hosted(DOMAIN) as hosted:
        yield hosted


def test_base_differential_and_pair_restore(bench: Bench, account: VirtualminAccount) -> None:  # noqa: PLR0915  # One linear workflow
    lab = bench.lab_of(account)
    data = DomainData(lab, account)
    management = VirtualminBackupManagementService(account.server)

    def fresh() -> VirtualminAccount:
        return VirtualminAccount.objects.get(pk=account.pk)

    # S0 -> base.
    token = secrets.token_hex(6)
    data.seed(token)
    data.write("keep.txt", "keep")
    data.write("change.txt", "v0")
    data.write("delete-me.txt", "gone soon")
    bench.clear_queue()
    admitted = management.take_base_backup(account, initiated_by="workflow")
    assert admitted.is_ok(), admitted
    base = admitted.unwrap()
    assert base.status == "pending" and base.parameters["chain_role"] == "base"
    bench.run_one("run_virtualmin_backup")
    base.refresh_from_db()
    assert base.status == "completed", (base.status, base.status_message)
    linked = fresh()
    assert linked.chain_base_id == base.pk, "the completed base is the account's live chain"
    pinned, epoch = linked.chain_base_fingerprint, linked.chain_epoch
    assert pinned and pinned != "ABSENT"
    assert "virtualmin_provisioning_job_completed" in bench.audit_actions(base)

    # S1: change, add, delete -> differential.
    data.write("change.txt", "v1")
    data.write("added.txt", "added")
    data.remove("delete-me.txt")
    bench.clear_queue()
    admitted = management.take_differential_backup(account, initiated_by="workflow")
    assert admitted.is_ok(), admitted
    diff = admitted.unwrap()
    assert diff.parameters["chain_role"] == "differential"
    assert diff.parameters["base_backup_id"] == base.result["backup_id"], "the differential is pinned to its base"
    bench.run_one("run_virtualmin_backup")
    diff.refresh_from_db()
    assert diff.status == "completed", (diff.status, diff.status_message)
    extended = fresh()
    assert (extended.chain_base_id, extended.chain_epoch, extended.chain_base_fingerprint) == (base.pk, epoch, pinned), (
        "a differential extends the chain and leaves the base and its snapshot where they were"
    )
    service = VirtualminBackupService(account.server)
    differential_manifest = service.read_manifest(diff.result["backup_id"]).unwrap()
    assert differential_manifest["chain_role"] == "differential"
    assert differential_manifest["base_backup_id"] == base.result["backup_id"], "the manifest names its base"
    assert bench.staged(account) == []

    # Damage, then restore the pair. It takes the domain offline behind a write barrier (proved in check 4d).
    data.write("change.txt", "damaged")
    data.remove("added.txt")
    bench.clear_queue()
    admitted = management.create_pair_restore_job(
        extended, base.result["backup_id"], diff.result["backup_id"], force_restore=True, initiated_by="workflow"
    )
    assert admitted.is_ok(), admitted
    pair = admitted.unwrap()
    assert pair.status == "pending"
    assert fresh().chain_base_id is None, "admitting a restore ends the chain before anything is dispatched"
    runs = bench.run_queue()
    assert [run.error for run in runs if run.error] == []
    assert runs[0].name == "run_virtualmin_restore"
    pair.refresh_from_db()
    assert pair.status == "completed", (pair.status, pair.status_message)
    assert "virtualmin_provisioning_job_completed" in bench.audit_actions(pair)

    # The data is the base plus the differential. Virtualmin does not replay deletions: the file removed
    # after the base comes back (documented in ADR-0059).
    assert data.read("change.txt") == "v1"
    assert data.read("added.txt") == "added"
    assert data.read("keep.txt") == "keep"
    assert data.read("delete-me.txt") == "gone soon"
    # The reconcile queued when the pair ended is the only writer of the enabled state (ADR-0051).
    assert "reconcile_virtualmin_service_state" in [run.name for run in runs]
    assert listing_enabled(lab.domain_values(DOMAIN)) is True
    restored = fresh()
    assert restored.status == "active"

    # The restore ended the chain: nothing to extend, and a differential is refused instead of run.
    assert restored.chain_base_id is None and restored.chain_epoch > epoch
    refused = management.take_differential_backup(restored)
    assert refused.is_err(), refused
    assert bench.staged(account) == []
