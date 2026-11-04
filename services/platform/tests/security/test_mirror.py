"""Complete snapshots advance atomically; every discarded delivery leaves its successor safe."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.db import IntegrityError, InterfaceError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.common.crowdsec_transport import CrowdSecRPCError
from apps.security import repos, services, tasks, transport
from apps.security.addresses import pack_address
from apps.security.models import SecurityAlert, SecurityDecision, SecuritySyncState
from tests.security.fixtures import SecurityFixture


class SecurityMirrorTests(SecurityFixture, TestCase):
    def queued(self):
        claim = repos.claim_for_queue(self.source.pk)
        self.assertIsNotNone(claim)
        return claim

    def poll(self, peer=None):
        queued = self.queued()
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=peer or self.peer()) as rpc:
            result = tasks.sync_source(str(self.source.pk), str(queued.token))
        return result, rpc

    def due(self):
        SecuritySyncState.objects.filter(source=self.source).update(next_run=timezone.now() - timedelta(seconds=1))

    def test_dispatch_coalesces_before_enqueue_and_a_delivery_is_consumed_once(self) -> None:
        with patch("apps.security.tasks.async_task") as queue:
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                self.assertEqual(tasks.dispatch_security_sync()["queued"], 1)
                self.assertEqual(tasks.dispatch_security_sync()["queued"], 0)
                queue.assert_not_called()
            self.assertEqual(len(callbacks), 1)
            callbacks[0]()
            queue.assert_called_once()
        token = SecuritySyncState.objects.get(source=self.source).claim_token
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()) as rpc:
            self.assertEqual(tasks.sync_source(str(self.source.pk), str(token))["state"], "ok")
            self.assertEqual(tasks.sync_source(str(self.source.pk), str(token))["state"], "superseded")
        self.assertEqual(rpc.call_count, 2)
        self.assertEqual(SecurityDecision.objects.get().value, "198.51.100.8/30")
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).alert_cursor, 1)
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).last_published_generation, 1)

    def test_alert_catchup_does_not_hold_decision_freshness_stale(self) -> None:
        first = [self.alert(index) for index in range(1, 1001)]
        result, _ = self.poll(self.peer(alerts=first, watermark=1000, has_more=True))
        self.assertEqual(result["state"], "catching_up")
        state = SecuritySyncState.objects.get(source=self.source)
        self.assertIsNotNone(state.last_decision_sync_at)
        self.assertIsNone(state.last_alert_sync_at)
        self.assertTrue(state.has_more)
        self.assertEqual(state.alert_cursor, 1000)
        self.due()
        self.poll(self.peer(alerts=[self.alert(index) for index in range(1001, 1006)], watermark=1005))
        state.refresh_from_db()
        self.assertEqual(SecurityAlert.objects.count(), 1005)
        self.assertEqual(state.alert_cursor, 1005)
        self.assertIsNotNone(state.last_alert_sync_at)
        self.assertFalse(state.has_more)

    def test_queue_publication_does_not_escape_a_rolled_back_transaction(self) -> None:
        with (
            patch("apps.security.tasks.async_task") as queue,
            self.captureOnCommitCallbacks(execute=True),
            self.assertRaisesMessage(RuntimeError, "rollback dispatch"),
            transaction.atomic(),
        ):
            self.assertEqual(tasks.dispatch_security_sync()["queued"], 1)
            raise RuntimeError("rollback dispatch")
        queue.assert_not_called()
        self.assertIsNone(SecuritySyncState.objects.get(source=self.source).claim_token)

    def test_range_alert_bounds_and_source_free_aggregate_alerts_are_queryable_without_scanning(self) -> None:
        ranged = {**self.alert(1), "scope": "range", "value": "2001:db8::8/126"}
        aggregate = {**self.alert(2), "scope": None, "value": None}
        self.poll(self.peer(alerts=[ranged, aggregate]))
        family, packed = pack_address("2001:db8::a")
        self.assertEqual(
            list(
                SecurityAlert.objects.filter(
                    address_family=family, network_start__lte=packed, network_end__gte=packed
                ).values_list("remote_id", flat=True)
            ),
            [1],
        )
        unknown = SecurityAlert.objects.get(remote_id=2)
        self.assertIsNone(unknown.address_family)
        self.assertIsNone(unknown.network_start)
        self.assertIsNone(unknown.network_end)

    def test_alert_address_constraint_rejects_a_missing_family_for_present_bounds(self) -> None:
        packed = pack_address("198.51.100.8")[1]
        with self.assertRaises(IntegrityError), transaction.atomic():
            SecurityAlert.objects.create(
                source=self.source,
                remote_id=1,
                source_created_at=self.now,
                scenario="crowdsecurity/ssh-bf",
                event_count=1,
                scope="ip",
                value="198.51.100.8",
                network_start=packed,
                network_end=packed,
            )

    def test_incomplete_or_wrong_identity_response_commits_neither_mirrors_nor_cursor(self) -> None:
        self.poll()
        original = SecuritySyncState.objects.get(source=self.source).last_decision_sync_at
        for bad in (
            "identity",
            "configuration",
            "raw_sample",
            "watermark",
            "too_many_alerts",
            "schema",
            "nonzero_exit",
            "truncated",
        ):

            def mutate(response, bad=bad):
                if response["operation"] != "snapshot":
                    return
                if bad == "identity":
                    response["installation_id"] = str(uuid4())
                elif bad == "configuration":
                    response["configuration_digest"] = "d" * 64
                elif bad in {"nonzero_exit", "truncated"}:
                    raise CrowdSecRPCError("transport refused partial output")
                elif bad == "raw_sample":
                    response["result"]["events"] = [{"password": "must-never-be-retained"}]
                elif bad == "watermark":
                    response["result"]["alert_watermark"] = 0
                elif bad == "too_many_alerts":
                    response["result"]["alerts"] = [self.alert(index) for index in range(2, 1003)]
                else:
                    response["result"]["decisions"][0]["unexpected"] = True

            with self.subTest(bad=bad):
                self.due()
                result, _ = self.poll(
                    self.peer(decisions=[self.decision(2, "198.51.100.12")], alerts=[self.alert(2)], mutate=mutate)
                )
                self.assertEqual(result["state"], "unavailable")
                state = SecuritySyncState.objects.get(source=self.source)
                self.assertEqual(state.alert_cursor, 1)
                self.assertEqual(state.last_decision_sync_at, original)
                self.assertEqual(SecurityDecision.objects.get().remote_id, 1)
                self.assertIsNone(SecurityDecision.objects.get().ended_at)
                self.assertEqual(SecurityAlert.objects.count(), 1)
                self.assertNotIn("must-never", str(state.health))

    def test_complete_decision_reconciliation_keeps_original_expiry_and_ended_history(self) -> None:
        self.poll()
        first = SecurityDecision.objects.get()
        self.due()
        self.poll(self.peer(decisions=[self.decision(2, "2001:db8::8/126")], alerts=[], watermark=1))
        first.refresh_from_db()
        self.assertIsNotNone(first.ended_at)
        self.assertEqual(first.expires_at.isoformat(), self.decision()["expires_at"])
        current = SecurityDecision.objects.get(remote_id=2)
        self.assertEqual(current.address_family, 6)
        self.assertEqual(bytes(current.network_start).hex(), "20010db8000000000000000000000008")
        self.assertEqual(bytes(current.network_end).hex(), "20010db800000000000000000000000b")
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).alert_cursor, 1)

    def test_remote_id_conflict_rejects_valid_siblings_and_cursor_as_one_batch(self) -> None:
        self.poll()
        self.due()
        result, _ = self.poll(
            self.peer(decisions=[self.decision(1, "198.51.100.20"), self.decision(2)], alerts=[self.alert(2)])
        )
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(SecurityDecision.objects.count(), 1)
        self.assertEqual(SecurityDecision.objects.get().value, "198.51.100.8/30")
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).alert_cursor, 1)

    def test_expiry_during_rpc_does_not_reopen_the_decision_or_discard_alert_catchup(self) -> None:
        decision = {**self.decision(), "expires_at": (self.now + timedelta(seconds=10)).isoformat()}
        self.poll(self.peer(decisions=[decision]))
        self.due()
        queued = self.queued()
        claim = repos.consume_claim(self.source.pk, queued.token)
        with patch(
            "apps.common.crowdsec_transport.remote_rpc",
            side_effect=self.peer(decisions=[decision], alerts=[self.alert(2)]),
        ):
            observation = transport.fetch(claim.connection, claim.alert_cursor)
        with patch("django.utils.timezone.now", return_value=self.now + timedelta(seconds=11)):
            tasks.prune_security_history()
            self.assertTrue(repos.publish_observation(claim, observation))
        row = SecurityDecision.objects.get()
        self.assertEqual(row.ended_at, row.expires_at)
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).alert_cursor, 2)

    def test_key_file_replacement_discards_an_already_fetched_reply(self) -> None:
        queued = self.queued()
        claim = repos.consume_claim(self.source.pk, queued.token)
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()):
            observation = transport.fetch(claim.connection, claim.alert_cursor)
        self.key.write_bytes(b"changed gateway identity")
        self.assertFalse(repos.publish_observation(claim, observation))
        self.assertEqual(SecurityDecision.objects.count(), 0)
        self.assertIsNone(repos.claim_for_queue(self.source.pk))
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).alert_cursor, 0)

    def test_stale_reply_after_reconfiguration_or_retirement_cannot_publish(self) -> None:
        for change in ("reconfigure", "retire"):
            with self.subTest(change=change):
                queued = self.queued()
                claim = repos.consume_claim(self.source.pk, queued.token)
                with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()):
                    observation = transport.fetch(claim.connection, claim.alert_cursor)
                if change == "reconfigure":
                    services.reconfigure_source(
                        self.source.pk, replace(self.config, hostname="new.example.test"), self.admin
                    )
                else:
                    services.retire_source(self.source.pk, self.admin)
                self.assertFalse(repos.publish_observation(claim, observation))
                self.assertEqual(SecurityDecision.objects.count(), 0)
                self.assertEqual(SecuritySyncState.objects.get(source=self.source).alert_cursor, 0)

    def test_crash_then_expired_lease_recovery_fences_the_previous_publication(self) -> None:
        queued = self.queued()
        claim = repos.consume_claim(self.source.pk, queued.token)
        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()):
            observation = transport.fetch(claim.connection, claim.alert_cursor)
        later = timezone.now() + timedelta(minutes=3)
        with patch("django.utils.timezone.now", return_value=later):
            replacement = repos.claim_for_queue(self.source.pk)
            self.assertIsNotNone(replacement)
            self.assertFalse(repos.publish_observation(claim, observation))
            with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=self.peer()):
                self.assertEqual(tasks.sync_source(str(self.source.pk), str(replacement.token))["state"], "ok")
        self.assertEqual(SecurityDecision.objects.count(), 1)

    def test_enqueue_uncertainty_invalidates_only_its_own_token(self) -> None:
        for failure in (TimeoutError, InterfaceError):
            with self.subTest(failure=failure.__name__):
                SecuritySyncState.objects.filter(source=self.source).update(next_run=timezone.now())
                with (
                    patch("apps.security.tasks.async_task", side_effect=failure("lost broker acknowledgement")),
                    self.captureOnCommitCallbacks(execute=True),
                ):
                    tasks.dispatch_security_sync()
                    old = SecuritySyncState.objects.get(source=self.source).claim_token
                with patch("apps.common.crowdsec_transport.remote_rpc") as rpc:
                    self.assertEqual(tasks.sync_source(str(self.source.pk), str(old))["state"], "superseded")
                    rpc.assert_not_called()
                state = SecuritySyncState.objects.get(source=self.source)
                self.assertIsNone(state.claim_token)
                self.assertEqual(state.outcome, "enqueue_failed")
