"""Issued action identities never turn uncertain remote application into a blind retry."""

import json
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import InterfaceError
from django.test import TestCase, override_settings

from apps.common import crowdsec_transport as gateway
from apps.security import action_repos, action_services, action_tasks, action_transport, services, transport
from apps.security.models import SecurityActionRequest, SecurityActionTarget, SecuritySyncState
from apps.users.models import User
from tests.security.action_fixtures import ActionFixture, prepare_replication


@override_settings(PRAHO_CROWDSEC_ACTIONS_ENABLED=True)
class SecurityActionTests(ActionFixture, TestCase):
    def test_real_gateway_schema_adapter_and_canonical_digest_bind_the_issued_target(self) -> None:
        target = self.issue().targets.get()
        self.assertEqual(target.payload_digest, gateway.canonical_action_digest(target.operation, target.payload))

        def peer(endpoint, raw):
            request = json.loads(raw)
            self.assertEqual(request["request_id"], str(target.request_id))
            self.assertEqual(request["payload"], target.payload)
            return {
                **{key: value for key, value in request.items() if key != "payload"},
                "result": self.receipt(target),
            }

        with patch("apps.common.crowdsec_transport.remote_rpc", side_effect=peer):
            result = action_transport.send_request(
                transport.capture_connection(self.source), target.operation, target.payload, target.request_id
            )
        self.assertEqual(result["status"], "succeeded")

    def test_issuance_is_persisted_and_idempotency_never_renews_portal_expiry(self) -> None:
        key = uuid4()
        request = self.issue(idempotency_key=key)
        target = request.targets.get()
        self.assertEqual(target.expires_at, request.created_at + timedelta(minutes=5))
        with patch("django.utils.timezone.now", return_value=self.now + timedelta(minutes=1)):
            self.assertEqual(self.issue(idempotency_key=key).pk, request.pk)
        target.refresh_from_db()
        self.assertEqual(target.expires_at, request.created_at + timedelta(minutes=5))
        self.assertEqual(SecurityActionTarget.objects.count(), 1)
        with self.assertRaises(ValidationError):
            action_services.issue_ban(
                actor=self.admin,
                reason="Different payload",
                idempotency_key=key,
                source_ids=[self.source.pk],
                scope="ip",
                value="198.51.100.8",
                duration_seconds=3600,
            )

    def test_only_admin_can_create_and_simulation_refuses_new_bans(self) -> None:
        support = User.objects.create_user(email="actions-support@example.test", staff_role="support")
        with self.assertRaises(PermissionDenied):
            action_services.issue_ban(
                actor=support,
                reason="Attack",
                idempotency_key=uuid4(),
                source_ids=[self.source.pk],
                scope="ip",
                value="198.51.100.8",
                duration_seconds=120,
            )
        state = SecuritySyncState.objects.get(source=self.source)
        state.health["simulation"] = True
        state.save(update_fields=["health"])
        with self.assertRaises(ValidationError):
            self.issue()

    def test_timeout_after_dispatch_stays_unknown_and_next_work_only_reads_receipt(self) -> None:
        target = self.issue().targets.get()
        with patch("apps.security.action_transport.send_request", side_effect=TimeoutError("after remote application")) as call:
            action_tasks.run_target(str(target.pk))
        target.refresh_from_db()
        self.assertEqual(target.state, "unknown")
        self.assertIsNotNone(target.dispatched_at)
        with patch(
            "apps.security.action_transport.send_request", return_value={"status": "unknown", "evidence": "no_receipt"}
        ) as call:
            action_tasks.run_target(str(target.pk))
        self.assertEqual(call.call_args.args[1], "receipt_get")
        target.refresh_from_db()
        self.assertEqual(target.state, "unknown")
        self.assertEqual(SecurityActionRequest.objects.get(pk=target.action_id).status, "unknown")

    def test_duplicate_claims_and_reconfiguration_fence_a_prepared_dispatch(self) -> None:
        target = self.issue().targets.get()
        first = action_repos.claim_target(target.pk)
        self.assertIsNotNone(first)
        self.assertIsNone(action_repos.claim_target(target.pk))
        first = action_repos.consume_target(target.pk, first.token)
        self.assertIsNotNone(first)
        services.reconfigure_source(self.source.pk, replace(self.config, hostname="changed.example.test"), self.admin)
        self.assertFalse(action_repos.mark_dispatched(first))
        target.refresh_from_db()
        self.assertEqual(target.state, "superseded")
        self.assertEqual(SecurityActionRequest.objects.get(pk=target.action_id).status, "superseded")

    def test_elapsed_undispatched_batch_is_expired_without_claiming_verified_completion(self) -> None:
        target = self.issue().targets.get()
        with (
            patch("django.utils.timezone.now", return_value=self.now + timedelta(minutes=6)),
            patch("apps.security.action_transport.send_request") as rpc,
        ):
            action_tasks.run_target(str(target.pk))
        rpc.assert_not_called()
        self.assertEqual(SecurityActionRequest.objects.get(pk=target.action_id).status, "expired")

    def test_mixed_verified_and_unapplied_targets_are_partial(self) -> None:
        prepare_replication(self)
        request = action_services.issue_ban(
            actor=self.admin,
            reason="Confirmed multi-host attack",
            idempotency_key=uuid4(),
            source_ids=[self.source.pk, self.target.pk],
            scope="ip",
            value="198.51.100.8",
            duration_seconds=120,
        )
        verified = request.targets.get(source=self.source)
        skipped = request.targets.get(source=self.target)
        with patch("apps.security.action_transport.send_request", return_value=self.receipt(verified)):
            action_tasks.run_target(str(verified.pk))
        services.retire_source(self.target.pk, self.admin)
        action_tasks.run_target(str(skipped.pk))
        request.refresh_from_db()
        self.assertEqual(request.status, "partial")

    def test_dispatch_claims_before_enqueue_and_rolled_back_dispatch_never_publishes(self) -> None:
        target = self.issue().targets.get()
        with patch("apps.security.action_tasks.async_task") as queue:
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                self.assertEqual(action_tasks.dispatch_actions()["queued"], 1)
                self.assertEqual(action_tasks.dispatch_actions()["queued"], 0)
            queue.assert_not_called()
            self.assertEqual(len(callbacks), 1)
            callbacks[0]()
            queue.assert_called_once()
        target.refresh_from_db()
        self.assertEqual(target.claim_phase, "queued")

    @override_settings(PRAHO_CROWDSEC_ACTIONS_ENABLED=False)
    def test_disabled_mutation_facility_rejects_new_staff_issuance(self) -> None:
        with self.assertRaises(ValidationError):
            self.issue()
        self.assertFalse(SecurityActionRequest.objects.exists())

    def test_queue_connection_failure_invalidates_the_undispatched_claim(self) -> None:
        target = self.issue().targets.get()
        claim = action_repos.claim_target(target.pk)
        self.assertIsNotNone(claim)
        with patch("apps.security.action_tasks.async_task", side_effect=InterfaceError("fixture queue disconnected")):
            action_tasks._enqueue(claim)
        target.refresh_from_db()
        self.assertIsNone(target.claim_token)
        self.assertIsNone(target.dispatched_at)
        with patch("apps.security.action_transport.send_request") as rpc:
            result = action_tasks.execute_claim(str(target.pk), str(claim.token))
        self.assertEqual(result["state"], "superseded")
        rpc.assert_not_called()

    def test_disabling_mutations_keeps_existing_unknown_receipt_reads_available(self) -> None:
        target = self.issue().targets.get()
        with patch("apps.security.action_transport.send_request", side_effect=TimeoutError("after application")):
            action_tasks.run_target(str(target.pk))
        with (
            override_settings(PRAHO_CROWDSEC_ACTIONS_ENABLED=False),
            patch(
                "apps.security.action_transport.send_request", return_value={"status": "unknown", "evidence": "no_receipt"}
            ) as rpc,
        ):
            action_tasks.run_target(str(target.pk))
        self.assertEqual(rpc.call_count, 1)
        self.assertEqual(rpc.call_args.args[1], "receipt_get")

    def test_positive_readonly_late_create_evidence_allows_only_same_revoke_replay(self) -> None:
        prepare_replication(self)
        request = action_services.issue_revoke(
            actor=self.admin,
            reason="Remove confirmed false positive",
            idempotency_key=uuid4(),
            decision_id=self.decision.pk,
        )
        target = request.targets.get()
        uncertain = self.receipt(target, status="unknown", evidence="mutation_uncertain")
        with patch("apps.security.action_transport.send_request", return_value=uncertain):
            action_tasks.run_target(str(target.pk))
        with patch("apps.security.action_transport.send_request", side_effect=[uncertain, self.receipt(target)]) as rpc:
            action_tasks.run_target(str(target.pk))
        self.assertEqual([call.args[1] for call in rpc.call_args_list], ["receipt_get", "revoke"])
        self.assertEqual(rpc.call_args_list[1].args[3], target.request_id)
        self.assertEqual(rpc.call_args_list[1].args[2], target.payload)
        target.refresh_from_db()
        self.assertEqual(target.state, "succeeded")

    def test_revoke_replay_keeps_unknown_if_enrollment_changes_after_receipt_read(self) -> None:
        prepare_replication(self)
        target = action_services.issue_revoke(
            actor=self.admin, reason="Remove false positive", idempotency_key=uuid4(), decision_id=self.decision.pk
        ).targets.get()
        uncertain = self.receipt(target, status="unknown", evidence="mutation_uncertain")
        with patch("apps.security.action_transport.send_request", return_value=uncertain):
            action_tasks.run_target(str(target.pk))

        def changed(*args):
            services.reconfigure_source(
                self.source.pk, replace(self.config, hostname="reviewed-new.example.test"), self.admin
            )
            return uncertain

        with patch("apps.security.action_transport.send_request", side_effect=changed) as rpc:
            action_tasks.run_target(str(target.pk))
        self.assertEqual(rpc.call_count, 1)
        target.refresh_from_db()
        self.assertEqual(target.state, "unknown")

    def test_allowlist_replacement_rejects_stale_staff_forms_but_replayed_identity_is_stable(self) -> None:
        key = uuid4()
        first = action_services.replace_allowlist(
            actor=self.admin,
            reason="Protect support network",
            idempotency_key=key,
            source_id=self.source.pk,
            cidrs=["198.51.100.8/32"],
            expected_revision=0,
        )
        second = action_services.replace_allowlist(
            actor=self.admin,
            reason="Protect current network",
            idempotency_key=uuid4(),
            source_id=self.source.pk,
            cidrs=["203.0.113.8/32"],
            expected_revision=1,
        )
        with self.assertRaises(ValidationError):
            action_services.replace_allowlist(
                actor=self.admin,
                reason="Stale browser form",
                idempotency_key=uuid4(),
                source_id=self.source.pk,
                cidrs=[],
                expected_revision=0,
            )
        replay = action_services.replace_allowlist(
            actor=self.admin,
            reason="Protect support network",
            idempotency_key=key,
            source_id=self.source.pk,
            cidrs=["198.51.100.8/32"],
            expected_revision=0,
        )
        self.assertEqual(replay.pk, first.pk)
        self.assertEqual(second.targets.get().revision, 2)

    def test_observed_late_allowlist_overlap_can_be_repaired_without_replaying_any_create(self) -> None:
        target = action_services.replace_allowlist(
            actor=self.admin,
            reason="Protect customer address",
            idempotency_key=uuid4(),
            source_id=self.source.pk,
            cidrs=["198.51.100.8/32"],
        ).targets.get()
        uncertain = self.receipt(target, status="unknown", evidence="mutation_uncertain")
        with patch("apps.security.action_transport.send_request", return_value=uncertain):
            action_tasks.run_target(str(target.pk))
        with patch("apps.security.action_transport.send_request", side_effect=[uncertain, self.receipt(target)]) as rpc:
            action_tasks.run_target(str(target.pk))
        self.assertEqual([call.args[1] for call in rpc.call_args_list], ["receipt_get", "allowlist_replace"])
        self.assertEqual(rpc.call_args_list[1].args[3], target.request_id)

    def test_newer_desired_allowlist_does_not_erase_an_uncertain_predecessor(self) -> None:
        target = action_services.replace_allowlist(
            actor=self.admin,
            reason="Protect first address",
            idempotency_key=uuid4(),
            source_id=self.source.pk,
            cidrs=["198.51.100.8/32"],
        ).targets.get()
        with patch("apps.security.action_transport.send_request", side_effect=TimeoutError("after application")):
            action_tasks.run_target(str(target.pk))
        action_services.replace_allowlist(
            actor=self.admin,
            reason="Protect new address",
            idempotency_key=uuid4(),
            source_id=self.source.pk,
            cidrs=["203.0.113.8/32"],
        )
        uncertain = self.receipt(target, status="unknown", evidence="mutation_uncertain")
        with patch("apps.security.action_transport.send_request", return_value=uncertain) as rpc:
            action_tasks.run_target(str(target.pk))
        self.assertEqual(rpc.call_count, 1)
        target.refresh_from_db()
        self.assertEqual(target.state, "unknown")
