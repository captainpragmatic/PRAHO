"""Workflow: moving accounts between nodes, one at a time and by draining a node (A to B).

A migration quiesces the account on the source, backs it up, moves the archive through the controller's spool,
restores it on the target and only then repoints the account (ADR-0051 keeps the reconciler out meanwhile). A
drain walks every account on a node through that migration. Both assert the data on B, the migration and drain
rows, the audit trail and the retained, disabled copy on A. The drain test moves the lab's round-trip account
too (it lives on vm-a), and puts everything back so the next `make test-virtualmin-lab` finds the lab as it was.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest

from apps.provisioning.virtualmin_backup_service import REMOTE_ARCHIVE_DIR
from apps.provisioning.virtualmin_drain_service import NodeDrainService
from apps.provisioning.virtualmin_gateway import listing_enabled
from apps.provisioning.virtualmin_migration_models import NodeDrain, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.virtualmin_lab.workflows.harness import Bench, DomainData

MOVE_DOMAIN = "wfmove.example.com"
DRAIN_DOMAIN = "wfdrain.example.com"
ROUNDTRIP_DOMAIN = "roundtrip.praho.test"


@pytest.fixture
def moving(bench: Bench) -> Iterator[VirtualminAccount]:
    bench.refresh_health()
    with bench.hosted(MOVE_DOMAIN) as account:
        yield account


def test_migration_moves_an_account_and_its_data_from_a_to_b(bench: Bench, moving: VirtualminAccount) -> None:
    source, target = bench.lab("vm-a"), bench.lab("vm-b")
    data = DomainData(source, moving)
    data.seed(secrets.token_hex(6))
    before = data.snapshot()
    counts_before = bench.server("vm-b").current_domains
    bench.clear_queue()

    started = VirtualminMigrationService().start_migration(
        moving, bench.server("vm-b"), initiated_by=None, reason="manual"
    )
    assert started.is_ok(), started
    migration = started.unwrap()
    assert migration.status == "pending"
    assert bench.queued() == ["run_virtualmin_migration"]
    runs = bench.run_queue()
    assert [run.error for run in runs if run.error] == []

    # PRAHO
    migration.refresh_from_db()
    assert migration.status == "completed", (migration.status, migration.error_detail)
    moving.refresh_from_db()
    assert bench.key_of(moving.server) == "vm-b"
    assert moving.status == "active"
    assert bench.server("vm-b").current_domains == counts_before + 1
    assert {"virtualmin_migration_started", "virtualmin_migration_completed"} <= set(bench.audit_actions(migration))
    assert "reconcile_virtualmin_service_state" in [run.name for run in runs], "the reconciler converges afterwards"
    assert not VirtualminMigration.objects.filter(account=moving).exclude(status="completed").exists()

    # The node: serving on B with the same data, a quiesced copy retained on A.
    assert target.domain_exists(MOVE_DOMAIN)
    assert listing_enabled(target.domain_values(MOVE_DOMAIN)) is True
    assert DomainData(target, moving).snapshot() == before, "files and rows arrived on B unchanged"
    assert source.domain_exists(MOVE_DOMAIN)
    assert listing_enabled(source.domain_values(MOVE_DOMAIN)) is False, "the source copy is kept, disabled"
    # The archive is kept on both nodes until an operator removes it; its sidecars (database passwords) are not.
    for lab in (source, target):
        left = lab.exec("ls", "-1A", REMOTE_ARCHIVE_DIR).split()
        assert [name for name in left if name.endswith((".dom", ".info"))] == [], left
        assert [name for name in left if name.startswith("migration_")] == [f"migration_{migration.pk}.tar.gz"], left


def test_drain_moves_every_account_off_a_node_and_the_lab_is_put_back(bench: Bench) -> None:
    bench.refresh_health()
    roundtrip = VirtualminAccount.objects.get(domain=ROUNDTRIP_DOMAIN)
    assert bench.key_of(roundtrip.server) == "vm-a", "the lab's round-trip account lives on vm-a"
    roundtrip_files = DomainData(bench.lab("vm-a"), roundtrip).files()
    # Only the node's own state is restored below; the flags a drain sets on vm-a are put back by the bench.
    bench.set_server_fields("vm-a", is_draining=False, status="active")
    with bench.hosted(DRAIN_DOMAIN) as account:
        data = DomainData(bench.lab("vm-a"), account)
        data.seed(secrets.token_hex(6))
        before = data.snapshot()
        try:
            started = NodeDrainService.start_drain(bench.server("vm-a"), initiated_by=None)
            assert started.is_ok(), started
            drain = started.unwrap()
            assert drain.accounts_total == 2, "the workflow account and the round-trip account"
            assert bench.server("vm-a").is_draining is True
            assert bench.queued() == ["run_node_drain"]
            runs = bench.run_queue()
            assert [run.error for run in runs if run.error] == []

            drain.refresh_from_db()
            assert drain.status == "completed", (drain.status, drain.error_detail)
            assert (drain.accounts_migrated, drain.accounts_skipped) == (2, 0)
            assert {"node_drain_started", "node_drain_completed"} <= set(bench.audit_actions(drain))
            for moved in (account, roundtrip):
                moved.refresh_from_db()
                assert bench.key_of(moved.server) == "vm-b", moved.domain
                assert bench.lab("vm-b").domain_exists(moved.domain)
                assert listing_enabled(bench.lab("vm-b").domain_values(moved.domain)) is True
            assert not VirtualminAccount.objects.filter(server=bench.server("vm-a"), status="active").exists()
            assert DomainData(bench.lab("vm-b"), account).snapshot() == before, "the workflow account's data is on B"
            assert DomainData(bench.lab("vm-b"), roundtrip).files() == roundtrip_files, "so is the round-trip account's"
            assert NodeDrain.objects.filter(server=bench.server("vm-a")).exclude(status="completed").count() == 0
        finally:
            bench.set_server_fields("vm-a", is_draining=False, status="active")
            bench.return_to(roundtrip, "vm-a")
            bench.lab("vm-b").remove_domain(ROUNDTRIP_DOMAIN)
            for lab in (bench.lab("vm-a"), bench.lab("vm-b")):
                lab.exec("sh", "-c", 'rm -f "$1"/migration_*', "sh", REMOTE_ARCHIVE_DIR)
    roundtrip.refresh_from_db()
    assert bench.key_of(roundtrip.server) == "vm-a"
    assert DomainData(bench.lab("vm-a"), roundtrip).files() == roundtrip_files, "the round-trip data is back on vm-a"
