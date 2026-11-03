"""Real PostgreSQL ownership waits, consumed deliveries and stale publication fences."""

from dataclasses import replace
from datetime import timedelta
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.db import connection, transaction
from django.test import TransactionTestCase, tag
from django.utils import timezone

from apps.provisioning.crowdsec_policy import CROWDSEC_PROFILE
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import select_security_profile
from apps.security import repos, services, tasks, transport
from apps.security.models import SecurityAlert, SecurityDecision, SecuritySource, SecuritySyncState
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.provisioning.test_node_security_policy import OPERATOR_KEY
from tests.security.fixtures import SecurityFixture


@tag("crowdsec")
class SecurityPostgresOwnershipTests(SecurityFixture, TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Security ownership and publication require real PostgreSQL row locks")
        super().setUp()

    def _wait_against_source_writer(self, action, writer):
        started = Event()
        owner = backend_pid()

        def reader():
            if not started.wait(10):
                raise TimeoutError("Source writer did not release its test barrier")
            return action()

        with database_worker(reader) as (pid, pending):
            try:
                with transaction.atomic():
                    SecuritySource.objects.select_for_update().get(pk=self.source.pk)
                    started.set()
                    wait_for_blocker(pid, owner, pending, table=SecuritySource._meta.db_table)
                    current = writer()
            finally:
                started.set()
            return current, pending.result(timeout=30)

    def test_duplicate_dispatch_claims_coalesce_under_an_observed_source_lock(self) -> None:
        first, second = self._wait_against_source_writer(
            lambda: repos.claim_for_queue(self.source.pk), lambda: repos.claim_for_queue(self.source.pk)
        )
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).claim_token, first.token)

    def test_duplicate_delivery_cannot_share_the_publication_token(self) -> None:
        queued = repos.claim_for_queue(self.source.pk)
        first, second = self._wait_against_source_writer(
            lambda: repos.consume_claim(self.source.pk, queued.token),
            lambda: repos.consume_claim(self.source.pk, queued.token),
        )
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertNotEqual(first.token, queued.token)
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).claim_token, first.token)

    def test_reconfiguration_wins_before_a_waiting_publisher_without_advancing_cursors(self) -> None:
        self._stale_publish("reconfigure")

    def test_retirement_wins_before_a_waiting_publisher_without_claiming_remote_revoke(self) -> None:
        self._stale_publish("retire")

    def _stale_publish(self, operation):
        queued = repos.claim_for_queue(self.source.pk)
        claim = repos.consume_claim(self.source.pk, queued.token)
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()):
            observation = transport.fetch(claim.connection, claim.alert_cursor)

        def write():
            if operation == "retire":
                return services.retire_source(self.source.pk, self.admin)
            return services.reconfigure_source(
                self.source.pk, replace(self.config, hostname="reconfigured.example.test"), self.admin
            )

        changed, published = self._wait_against_source_writer(
            lambda: repos.publish_observation(claim, observation), write
        )
        self.assertFalse(published)
        self.assertEqual(changed.generation, 2)
        self.assertEqual(SecurityDecision.objects.count(), 0)
        self.assertEqual(SecurityAlert.objects.count(), 0)
        state = SecuritySyncState.objects.get(source=self.source)
        self.assertEqual(state.alert_cursor, 0)
        self.assertEqual(state.last_published_generation, 0)

    def test_network_io_does_not_hold_source_locks_and_drift_discards_the_reply(self) -> None:
        queued = repos.claim_for_queue(self.source.pk)
        peer = self.peer()
        seen = []

        def remote(endpoint, raw):
            if not seen:
                with database_worker(
                    lambda: services.reconfigure_source(
                        self.source.pk, replace(self.config, hostname="changed-during-io.example.test"), self.admin
                    )
                ) as (_, pending):
                    seen.append(pending.result(timeout=10).generation)
            return peer(endpoint, raw)

        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=remote):
            self.assertEqual(tasks.sync_source(str(self.source.pk), str(queued.token))["state"], "superseded")
        self.assertEqual(seen, [2])
        self.assertEqual(SecurityDecision.objects.count(), 0)
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).alert_cursor, 0)

    def test_crashed_claim_expiry_and_old_replay_cannot_clear_or_publish_successor(self) -> None:
        queued = repos.claim_for_queue(self.source.pk)
        old = repos.consume_claim(self.source.pk, queued.token)
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()):
            observation = transport.fetch(old.connection, old.alert_cursor)
        later = timezone.now() + timedelta(minutes=3)
        with patch("django.utils.timezone.now", return_value=later):
            owner = backend_pid()
            with transaction.atomic():
                SecuritySource.objects.select_for_update().get(pk=self.source.pk)
                replacement = repos.claim_for_queue(self.source.pk)
            with database_worker(lambda: repos.publish_observation(old, observation)) as (pid, pending):
                self.assertNotEqual(pid, owner)
                self.assertFalse(pending.result(timeout=10))
            state = SecuritySyncState.objects.get(source=self.source)
            self.assertEqual(state.claim_token, replacement.token)
            self.assertFalse(repos.fail_claim(self.source.pk, old.token, "unavailable"))
            with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()):
                self.assertEqual(tasks.sync_source(str(self.source.pk), str(replacement.token))["state"], "ok")
        self.assertEqual(SecurityDecision.objects.count(), 1)
        self.assertEqual(SecurityAlert.objects.count(), 1)

    def test_node_identity_writer_wins_before_a_waiting_publisher(self) -> None:
        public = self.key.with_suffix(".pub")
        public.write_text(OPERATOR_KEY)
        configured = self.settings(PRAHO_CROWDSEC_SSH_PUBLIC_KEY_PATH=str(public))
        configured.enable()
        self.addCleanup(configured.disable)
        server = VirtualminServer.objects.create(hostname="node.example.test", api_username="praho-api")
        select_security_profile(server, CROWDSEC_PROFILE, self.admin, configuration_digest="c" * 64)
        config = replace(
            self.config, kind="node", hostname=server.hostname, virtualmin_server_id=server.pk, installation_id=uuid4()
        )
        source = services.enroll_source(config, self.admin)
        queued = repos.claim_for_queue(source.pk)
        claim = repos.consume_claim(source.pk, queued.token)
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()):
            observation = transport.fetch(claim.connection, claim.alert_cursor)
        started = Event()
        owner = backend_pid()

        def publish():
            if not started.wait(10):
                raise TimeoutError("Node writer did not release its test barrier")
            return repos.publish_observation(claim, observation)

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
        self.assertEqual(SecurityDecision.objects.filter(source=source).count(), 0)
        self.assertEqual(SecuritySyncState.objects.get(source=source).alert_cursor, 0)
