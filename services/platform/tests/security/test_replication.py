"""Explicit native coverage admits each hostile original to each host at most once."""

import json
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from apps.provisioning.virtualmin_security import _evidence_digest
from apps.provisioning.virtualmin_security_models import NodeSecurityReview
from apps.security import action_services, action_tasks, replication, services, tasks
from apps.security.action_transport import digest
from apps.security.addresses import address_bounds
from apps.security.models import (
    SecurityCoverageApproval,
    SecurityDecision,
    SecurityManagedDecision,
    SecurityReplication,
    SecuritySyncState,
)
from tests.security.action_fixtures import ActionFixture, prepare_node


@override_settings(PRAHO_CROWDSEC_ACTIONS_ENABLED=True, PRAHO_CROWDSEC_REPLICATION_ENABLED=True)
class SecurityReplicationTests(ActionFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        policy = {
            "schema": 1,
            "host_kind": "portal",
            "simulation": False,
            "protected_cidrs": ["127.0.0.0/8"],
            "artifact_lock_sha256": "a" * 64,
            "bouncer_binary_sha256": "b" * 64,
            "managed_files": {
                "/etc/crowdsec/acquis.yaml": sha256(replication.PORTAL_FILE_ACQUISITION.encode()).hexdigest()
            },
        }
        self.config = replace(self.config, configuration_digest=digest(policy))
        self.source = services.reconfigure_source(self.source.pk, self.config, self.admin)
        SecuritySyncState.objects.filter(source=self.source).update(
            last_published_generation=self.source.generation, outcome="ok"
        )
        self.target = services.enroll_source(
            replace(self.config, hostname="other-portal.example.test", installation_id=uuid4()), self.admin
        )
        state = SecuritySyncState.objects.get(source=self.source)
        SecuritySyncState.objects.filter(source=self.target).update(
            health=state.health, last_decision_sync_at=self.now, last_published_generation=1, outcome="ok"
        )
        self.proof = {
            "schema": 1,
            "installation_id": str(self.source.installation_id),
            "policy": policy,
            "acquisition_sha256": policy["managed_files"]["/etc/crowdsec/acquis.yaml"],
            "administrative_ssh": False,
            "ssh_journal_unit": None,
            "ssh_listener_port": None,
            "http_listener_port": 443,
            "portal_http_qualified": True,
            "qualification_sha256": "e" * 64,
        }
        bounds = address_bounds("ip", "198.51.100.8")
        self.decision = SecurityDecision.objects.create(
            source=self.source,
            remote_id=1,
            source_created_at=self.now,
            expires_at=self.now + timedelta(hours=4),
            scenario="crowdsecurity/http-cve-2021-41773",
            type="ban",
            scope="ip",
            value="198.51.100.8",
            origin="crowdsec",
            address_family=bounds.address_family,
            network_start=bounds.network_start,
            network_end=bounds.network_end,
        )

    def approve(self):
        return replication.approve_coverage(
            actor=self.admin,
            reason="Reviewed real ingress native qualification",
            source_id=self.source.pk,
            scenarios=[self.decision.scenario],
            evidence_digest=digest(self.proof),
            native_evidence=self.proof,
        )

    def test_no_approval_means_no_copy_and_valid_admission_never_renews(self) -> None:
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])
        self.approve()
        first = replication.replicate_decision(self.decision.pk)
        self.assertEqual(len(first), 1)
        replica = SecurityReplication.objects.get()
        self.assertEqual(replica.expires_at, first[0].created_at + timedelta(minutes=5))
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])
        replica.refresh_from_db()
        self.assertEqual(replica.expires_at, first[0].created_at + timedelta(minutes=5))

    def test_mapped_legacy_host_is_unmapped_only_for_new_copy_and_keeps_exact_revoke_summary(self) -> None:
        self.approve()
        self.decision.value = "::ffff:c633:6408"
        self.decision.save(update_fields=["value"])
        target = replication.replicate_decision(self.decision.pk)[0].targets.get()
        self.assertEqual(target.payload["value"], "198.51.100.8")
        self.decision.refresh_from_db()
        self.assertEqual(action_services.decision_fingerprint(self.decision)["value"], "::ffff:c633:6408")

    def test_claimed_scenario_without_exact_native_acquisition_or_proof_checksum_is_rejected(self) -> None:
        for field, value in (
            ("acquisition_sha256", "0" * 64),
            ("portal_http_qualified", False),
            ("qualification_sha256", "not-a-checksum"),
        ):
            proof = {**self.proof, field: value}
            with self.subTest(field=field), self.assertRaises(ValidationError):
                replication.approve_coverage(
                    actor=self.admin,
                    reason="Reviewed qualification",
                    source_id=self.source.pk,
                    scenarios=[self.decision.scenario],
                    evidence_digest=digest(proof),
                    native_evidence=proof,
                )
        self.assertFalse(SecurityCoverageApproval.objects.exists())

    def test_unapproved_authentication_probing_manual_simulated_and_unqualified_clocks_never_copy(self) -> None:
        self.approve()
        original = self.decision.scenario
        for scenario in (
            "crowdsecurity/http-probing",
            "andreasbrett/webmin-bf",
            "praho/portal-auth",
            "crowdsecurity/ssh-bf",
        ):
            self.decision.scenario = scenario
            self.decision.save(update_fields=["scenario"])
            self.assertEqual(replication.replicate_decision(self.decision.pk), [])
        self.decision.scenario, self.decision.origin = original, "cscli"
        self.decision.save(update_fields=["scenario", "origin"])
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])
        self.decision.origin, self.decision.simulated = "crowdsec", True
        self.decision.save(update_fields=["origin", "simulated"])
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])
        self.decision.simulated = False
        self.decision.save(update_fields=["simulated"])
        state = SecuritySyncState.objects.get(source=self.source)
        state.health["clock"]["qualified"] = False
        state.save(update_fields=["health"])
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])

    def test_revoke_suppresses_the_original_and_cancels_an_undispatched_copy(self) -> None:
        self.approve()
        created = replication.replicate_decision(self.decision.pk)[0]
        action = action_services.issue_revoke(
            actor=self.admin,
            reason="False positive after review",
            idempotency_key=uuid4(),
            decision_id=self.decision.pk,
        )
        self.assertEqual(action.targets.count(), 2)
        target = created.targets.get()
        target.refresh_from_db()
        self.assertEqual(target.state, "superseded")
        created.refresh_from_db()
        self.assertEqual(created.status, "superseded")
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])

    def test_revoking_a_known_replica_resolves_its_original_and_all_sibling_copies(self) -> None:
        self.approve()
        replica_action = replication.replicate_decision(self.decision.pk)[0]
        admitted = SecurityReplication.objects.get()
        local = SecurityDecision.objects.get(pk=self.decision.pk)
        local.pk = uuid4()
        local.source = self.target
        local.remote_id = 90
        local.origin, local.scenario = "cscli", "cscli/manual"
        local.save(force_insert=True)
        SecurityManagedDecision.objects.create(
            source=self.target,
            remote_id=90,
            provenance_id=admitted.provenance_id,
            issuing_target=replica_action.targets.get(),
        )
        request = action_services.issue_revoke(
            actor=self.admin,
            reason="Revoke this hostile original everywhere",
            idempotency_key=uuid4(),
            decision_id=local.pk,
        )
        self.assertEqual(request.decision_id, self.decision.pk)
        self.assertEqual(request.targets.count(), 2)

    def test_action_provenance_survives_ninety_day_mirror_retention(self) -> None:
        self.approve()
        replica_action = replication.replicate_decision(self.decision.pk)[0]
        revoke = action_services.issue_revoke(
            actor=self.admin, reason="Reviewed false positive", idempotency_key=uuid4(), decision_id=self.decision.pk
        )
        with patch("django.utils.timezone.now", return_value=self.now + timedelta(days=91)):
            tasks.prune_security_history()
        self.assertFalse(SecurityDecision.objects.filter(pk=self.decision.pk).exists())
        replica_action.refresh_from_db()
        revoke.refresh_from_db()
        self.assertIsNone(replica_action.decision_id)
        self.assertIsNone(revoke.decision_id)
        self.assertEqual(SecurityReplication.objects.get().origin_remote_id, self.decision.remote_id)

    def test_bounded_dispatch_rotates_past_already_admitted_decisions(self) -> None:
        self.approve()
        fields = {
            name: getattr(self.decision, name)
            for name in (
                "source_created_at",
                "expires_at",
                "scenario",
                "type",
                "scope",
                "value",
                "origin",
                "address_family",
                "network_start",
                "network_end",
            )
        }
        SecurityDecision.objects.bulk_create(
            [SecurityDecision(source=self.source, remote_id=index, **fields) for index in range(2, 102)]
        )
        self.assertEqual(replication.dispatch_replication()["admitted"], 100)
        self.assertEqual(replication.dispatch_replication()["admitted"], 1)
        self.assertEqual(SecurityReplication.objects.count(), 101)

    def test_withdrawal_is_audited_and_cancels_queued_copy_authority(self) -> None:
        approval = self.approve()
        replica = replication.replicate_decision(self.decision.pk)[0].targets.get()
        replication.withdraw_coverage(
            actor=self.admin, reason="Withdraw detection qualification", source_id=self.source.pk
        )
        approval.refresh_from_db()
        self.assertIsNotNone(approval.revoked_at)
        self.assertEqual(replication.replicate_decision(self.decision.pk), [])

        with patch("apps.security.action_transport.send_request") as rpc:
            action_tasks.run_target(str(replica.pk))
        rpc.assert_not_called()

    def test_expired_original_summary_refuses_replica_revoke_with_bounded_validation(self) -> None:
        self.approve()
        replica_action = replication.replicate_decision(self.decision.pk)[0]
        admitted = SecurityReplication.objects.get()
        local = SecurityDecision.objects.get(pk=self.decision.pk)
        local.pk, local.source, local.remote_id = uuid4(), self.target, 90
        local.origin, local.scenario = "cscli", "cscli/manual"
        local.save(force_insert=True)
        SecurityManagedDecision.objects.create(
            source=self.target,
            remote_id=90,
            provenance_id=admitted.provenance_id,
            issuing_target=replica_action.targets.get(),
        )
        self.decision.delete()
        with self.assertRaises(ValidationError):
            action_services.issue_revoke(
                actor=self.admin, reason="Revoke retained replica", idempotency_key=uuid4(), decision_id=local.pk
            )

    def test_admin_journal_and_listener_alone_never_prove_customer_sftp_exclusion(self) -> None:
        source, _server, _review, proof = prepare_node(self)
        with self.assertRaises(ValidationError):
            replication.approve_coverage(
                actor=self.admin,
                reason="Reviewed native admin SSH",
                source_id=source.pk,
                scenarios=["crowdsecurity/ssh-bf"],
                evidence_digest=digest(proof),
                native_evidence=proof,
                administrative_ssh=True,
            )

    def test_complete_admin_ssh_proof_is_accepted_and_cannot_borrow_another_physical_review(self) -> None:
        source, server, review, proof = prepare_node(self)
        proof.update(ssh_exclusive_administrative=True, customer_sftp_excluded=True)
        approved = replication.approve_coverage(
            actor=self.admin,
            reason="Verified dedicated admin SSH plus tenant exclusion",
            source_id=source.pk,
            scenarios=["crowdsecurity/ssh-bf"],
            evidence_digest=digest(proof),
            native_evidence=proof,
            administrative_ssh=True,
        )
        self.assertEqual(approved.review_id, review.pk)

        evidence = {
            **review.evidence,
            "services": [row for row in review.evidence["services"] if not row.startswith("PRAHO_CROWDSEC_CONFIG ")],
        }
        evidence["services"].append(
            "PRAHO_CROWDSEC_CONFIG "
            + json.dumps(
                {
                    "configuration_digest": source.configuration_digest,
                    "configuration_sha256": "f" * 64,
                    "installation_id": str(uuid4()),
                    "root_owned": True,
                }
            )
        )
        other = NodeSecurityReview.objects.create(
            server=server,
            server_uuid=server.pk,
            policy_version=review.policy_version,
            identity=review.identity,
            evidence=evidence,
            digest=_evidence_digest(evidence, policy_version=review.policy_version),
        )
        server.verified_security_review = other
        server.save(update_fields=["verified_security_review"])
        with self.assertRaises(ValidationError):
            replication.approve_coverage(
                actor=self.admin,
                reason="This review belongs to another physical LAPI",
                source_id=source.pk,
                scenarios=["crowdsecurity/ssh-bf"],
                evidence_digest=digest(proof),
                native_evidence=proof,
                administrative_ssh=True,
            )
