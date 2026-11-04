"""Observed PostgreSQL waits and network barriers prove action ownership and delayed-create safety."""

from dataclasses import replace
from datetime import timedelta
from functools import partial
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.db import connection, transaction
from django.test import TransactionTestCase, override_settings

from apps.provisioning.virtualmin_models import VirtualminServer
from apps.security import action_repos, action_services, action_tasks, replication, services
from apps.security.models import SecurityActionRequest, SecuritySource, SecuritySyncState
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.security.action_fixtures import (
    ActionFixture,
    ActionPeer,
    approve_replication,
    prepare_node,
    prepare_replication,
)


@override_settings(PRAHO_CROWDSEC_ACTIONS_ENABLED=True, PRAHO_CROWDSEC_REPLICATION_ENABLED=True)
class SecurityActionPostgresTests(ActionFixture, TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("Action ownership requires actual PostgreSQL locks and independent connections")
        super().setUp()

    def wait_source(self, source, action, writer):
        start = Event()
        owner = backend_pid()

        def read():
            if not start.wait(10):
                raise TimeoutError("Source writer barrier was not released")
            return action()

        with database_worker(read) as (pid, pending):
            try:
                with transaction.atomic():
                    SecuritySource.objects.select_for_update().get(pk=source.pk)
                    start.set()
                    wait_for_blocker(pid, owner, pending, table=SecuritySource._meta.db_table)
                    first = writer()
            finally:
                start.set()
            return first, pending.result(timeout=30)

    def prepare(self, target):
        queued = action_repos.claim_target(target.pk)
        claim = action_repos.consume_target(target.pk, queued.token)
        self.assertTrue(action_repos.mark_dispatched(claim))
        return claim

    def test_duplicate_target_claims_coalesce_under_observed_source_lock(self) -> None:
        target = self.issue().targets.get()
        first, duplicate = self.wait_source(
            self.source, lambda: action_repos.claim_target(target.pk), lambda: action_repos.claim_target(target.pk)
        )
        self.assertIsNotNone(first)
        self.assertIsNone(duplicate)

    def test_duplicate_delivery_rotates_into_a_single_publication_identity(self) -> None:
        target = self.issue().targets.get()
        queued = action_repos.claim_target(target.pk)
        first, duplicate = self.wait_source(
            self.source,
            lambda: action_repos.consume_target(target.pk, queued.token),
            lambda: action_repos.consume_target(target.pk, queued.token),
        )
        self.assertIsNotNone(first)
        self.assertIsNone(duplicate)
        self.assertNotEqual(first.token, queued.token)

    def test_crash_after_remote_application_recovers_by_receipt_without_second_create(self) -> None:
        target = self.issue().targets.get()
        peer = ActionPeer(self)

        def crash(*args):
            peer(*args)
            raise SystemExit("Worker crashed after remote commit")

        with patch("apps.security.action_transport.call", side_effect=crash), self.assertRaises(SystemExit):
            action_tasks.run_target(str(target.pk))
        target.refresh_from_db()
        self.assertEqual(target.state, "dispatching")
        with (
            patch("django.utils.timezone.now", return_value=self.now + timedelta(seconds=121)),
            patch("apps.security.action_transport.call", side_effect=peer),
        ):
            action_tasks.run_target(str(target.pk))
        target.refresh_from_db()
        self.assertEqual(target.state, "succeeded")
        self.assertEqual(peer.operations, ["ban_put", "receipt_get"])

    def test_retirement_and_reconfiguration_fence_a_waiting_result_without_losing_uncertainty(self) -> None:
        for operation in ("retire", "reconfigure"):
            with self.subTest(operation=operation):
                source = (
                    self.source
                    if operation == "retire"
                    else services.enroll_source(
                        replace(self.config, hostname="second.example.test", installation_id=uuid4()), self.admin
                    )
                )
                if source != self.source:
                    original = SecuritySyncState.objects.get(source=self.source)
                    SecuritySyncState.objects.filter(source=source).update(
                        health=original.health,
                        last_decision_sync_at=self.now,
                        last_published_generation=1,
                        outcome="ok",
                    )
                request = action_services.issue_ban(
                    actor=self.admin,
                    reason="Confirmed attack",
                    idempotency_key=uuid4(),
                    source_ids=[source.pk],
                    scope="ip",
                    value="198.51.100.8",
                    duration_seconds=120,
                )
                target = request.targets.get()
                claim = self.prepare(target)
                receipt = self.receipt(target)
                writer = (
                    partial(services.retire_source, source.pk, self.admin)
                    if operation == "retire"
                    else (
                        partial(
                            services.reconfigure_source,
                            source.pk,
                            replace(
                                self.config, hostname="changed.example.test", installation_id=source.installation_id
                            ),
                            self.admin,
                        )
                    )
                )
                _, published = self.wait_source(source, partial(action_repos.record_result, claim, receipt), writer)
                self.assertFalse(published)
                target.refresh_from_db()
                self.assertEqual(target.state, "unknown")

    def test_key_rotation_after_dispatch_requires_explicit_review_before_receipt_reconciliation(self) -> None:
        target = self.issue().targets.get()
        claim = self.prepare(target)
        receipt = self.receipt(target)
        self.key.write_bytes(b"reviewed rotated gateway identity")
        self.assertFalse(action_repos.record_result(claim, receipt))
        target.refresh_from_db()
        self.assertEqual(target.state, "unknown")
        self.assertIsNone(action_repos.claim_target(target.pk))
        services.reconfigure_source(self.source.pk, self.config, self.admin)
        with patch("apps.security.action_transport.call", return_value=receipt) as rpc:
            action_tasks.run_target(str(target.pk))
        self.assertEqual(rpc.call_args.args[1], "receipt_get")
        target.refresh_from_db()
        self.assertEqual(target.state, "succeeded")

    def test_revoke_tombstone_wins_against_a_create_delayed_outside_database_locks(self) -> None:
        prepare_replication(self)
        approve_replication(self)
        creation = replication.replicate_decision(self.decision.pk)[0]
        target = creation.targets.get()
        peer = ActionPeer(self)
        entered, release = Event(), Event()

        def delayed(connection, operation, payload, request_id=None):
            if operation == "ban_put":
                entered.set()
                if not release.wait(15):
                    raise TimeoutError("Delayed create was not released")
            return peer(connection, operation, payload, request_id)

        with (
            patch("apps.security.action_transport.call", side_effect=delayed),
            database_worker(lambda: action_tasks.run_target(str(target.pk))) as (_, pending),
        ):
            try:
                self.assertTrue(entered.wait(10))
                with database_worker(
                    lambda: action_services.issue_revoke(
                        actor=self.admin,
                        reason="Confirmed false positive",
                        idempotency_key=uuid4(),
                        decision_id=self.decision.pk,
                    )
                ) as (_, issued):
                    revoke = issued.result(timeout=10)
                for item in revoke.targets.all():
                    action_tasks.run_target(str(item.pk))
                revoke.refresh_from_db()
                self.assertEqual(revoke.status, "unknown")
            finally:
                release.set()
            self.assertEqual(pending.result(timeout=15)["state"], "superseded")
        revoke.refresh_from_db()
        self.assertEqual(revoke.status, "complete")
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])
        self.assertEqual(peer.operations.count("ban_put"), 1)

    def test_node_connection_writer_wins_before_a_waiting_action_result(self) -> None:

        source, server, _review, _proof = prepare_node(self)
        target = action_services.issue_ban(
            actor=self.admin,
            reason="Confirmed administrative attack",
            idempotency_key=uuid4(),
            source_ids=[source.pk],
            scope="ip",
            value="198.51.100.8",
            duration_seconds=3600,
        ).targets.get()
        claim = self.prepare(target)
        receipt = self.receipt(target)
        started = Event()
        owner = backend_pid()

        def publish():
            if not started.wait(10):
                raise TimeoutError("Node writer barrier was not released")
            return action_repos.record_result(claim, receipt)

        with database_worker(publish) as (pid, pending):
            try:
                with transaction.atomic():
                    VirtualminServer.objects.select_for_update().get(pk=server.pk)
                    VirtualminServer.objects.filter(pk=server.pk).update(api_port=10001)
                    started.set()
                    wait_for_blocker(pid, owner, pending, table=VirtualminServer._meta.db_table)
            finally:
                started.set()
            self.assertFalse(pending.result(timeout=30))
        target.refresh_from_db()
        self.assertEqual(target.state, "unknown")

    def test_cross_source_result_aggregation_serializes_before_reading_target_states(self) -> None:
        prepare_replication(self)
        request = action_services.issue_ban(
            actor=self.admin,
            reason="Confirmed cross-host attack",
            idempotency_key=uuid4(),
            source_ids=[self.source.pk, self.target.pk],
            scope="ip",
            value="198.51.100.8",
            duration_seconds=120,
        )
        first, second = list(request.targets.order_by("pk"))
        first_claim, second_claim = self.prepare(first), self.prepare(second)
        first_receipt, second_receipt = self.receipt(first), self.receipt(second)
        start = Event()
        owner = backend_pid()

        def publish():
            if not start.wait(10):
                raise TimeoutError("Request writer barrier was not released")
            return action_repos.record_result(first_claim, first_receipt)

        with database_worker(publish) as (pid, pending):
            try:
                with transaction.atomic():
                    SecurityActionRequest.objects.select_for_update().get(pk=request.pk)
                    start.set()
                    wait_for_blocker(pid, owner, pending, table=SecurityActionRequest._meta.db_table)
                    self.assertTrue(action_repos.record_result(second_claim, second_receipt))
            finally:
                start.set()
            self.assertTrue(pending.result(timeout=30))
        request.refresh_from_db()
        self.assertEqual(request.status, "complete")

    def test_withdrawal_wins_before_an_observed_waiting_replica_admission(self) -> None:
        prepare_replication(self)
        approve_replication(self)
        _, admitted = self.wait_source(
            self.source,
            lambda: replication.replicate_decision(self.decision.pk),
            lambda: replication.withdraw_coverage(
                actor=self.admin, reason="Withdraw current provenance", source_id=self.source.pk
            ),
        )
        self.assertEqual(admitted, [])

    def test_revoke_reloads_replica_target_set_after_waiting_for_an_admission_writer(self) -> None:
        prepare_replication(self)
        approve_replication(self)
        _, revoke = self.wait_source(
            self.source,
            lambda: action_services.issue_revoke(
                actor=self.admin,
                reason="Revoke after competing admission",
                idempotency_key=uuid4(),
                decision_id=self.decision.pk,
            ),
            lambda: replication.replicate_decision(self.decision.pk),
        )
        self.assertEqual(revoke.targets.count(), 2)
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])
