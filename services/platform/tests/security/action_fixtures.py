"""Protocol-shaped action evidence; only the host boundary is replaced."""

import json
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from threading import Lock
from uuid import UUID, uuid4

from apps.provisioning.crowdsec_policy import CROWDSEC_PROFILE
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_security import _evidence_digest, connection_identity, select_security_profile
from apps.provisioning.virtualmin_security_models import NodeSecurityReview
from apps.security import action_services, replication, services
from apps.security.action_transport import digest
from apps.security.addresses import address_bounds
from apps.security.models import (
    SecurityActionRequest,
    SecurityActionTarget,
    SecurityCoverageApproval,
    SecurityDecision,
    SecuritySource,
    SecuritySyncState,
)
from apps.security.transport import SourceConnection
from tests.provisioning.test_node_security_policy import OPERATOR_KEY, node_policy_evidence
from tests.security.fixtures import SecurityFixture


class ActionFixture(SecurityFixture):
    def setUp(self) -> None:
        super().setUp()
        health = self.peer()(None, b'{"operation":"health"}')["result"]
        health.update(simulation=False, bouncer={"active": True, "version": "0.0.36-praho.1"})
        health["clock"].update(
            qualified=True,
            synchronized=True,
            offset_seconds=0.0,
            maximum_error_seconds=0.01,
            estimated_error_seconds=0.01,
        )
        SecuritySyncState.objects.filter(source=self.source).update(
            health=health,
            last_decision_sync_at=self.now,
            last_published_generation=self.source.generation,
            outcome="ok",
        )

    def issue(self, *, idempotency_key: UUID | None = None) -> SecurityActionRequest:
        return action_services.issue_ban(
            actor=self.admin,
            reason="Confirmed administrative attack",
            idempotency_key=idempotency_key or uuid4(),
            source_ids=[self.source.pk],
            scope="ip",
            value="198.51.100.8",
            duration_seconds=3600,
        )

    def receipt(
        self,
        target: SecurityActionTarget,
        *,
        status: str = "succeeded",
        evidence: str | None = None,
        ids: list[int] | None = None,
    ) -> dict[str, object]:
        return {
            "status": status,
            "evidence": evidence
            or {"ban_put": "decision_present", "revoke": "decision_absent", "allowlist_replace": "allowlist_matches"}[
                target.operation
            ],
            "request_id": str(target.request_id),
            "operation": target.operation,
            "payload_digest": target.payload_digest,
            "provenance_id": str(target.provenance_id) if target.provenance_id else None,
            "revision": target.revision,
            "decision_ids": ([90] if target.operation == "ban_put" else []) if ids is None else ids,
            "expires_at": target.expires_at.isoformat() if target.expires_at else None,
            "observed_at": self.now.isoformat(),
        }


class ActionPeer:
    """A receipt-persistent monotonic host, including a create delayed behind a tombstone."""

    def __init__(self, fixture: ActionFixture) -> None:
        self.fixture = fixture
        self.receipts = {}
        self.revisions = {}
        self.operations = []
        self.lock = Lock()

    def __call__(
        self, connection: SourceConnection, operation: str, payload: dict[str, object], request_id: UUID | None = None
    ) -> dict[str, object]:
        with self.lock:
            self.operations.append(operation)
            if operation == "receipt_get":
                return self.receipts.get(payload["request_id"], {"status": "unknown", "evidence": "no_receipt"})
            target = SecurityActionTarget.objects.get(request_id=request_id)
            key = (connection.source_id, payload.get("provenance_id"))
            previous = self.revisions.get(key, 0)
            if payload["revision"] < previous:
                result = self.fixture.receipt(target, status="superseded", evidence="newer_revision", ids=[])
            else:
                self.revisions[key] = payload["revision"]
                result = self.fixture.receipt(target)
            self.receipts[str(request_id)] = result
            return result


def prepare_replication(fixture: ActionFixture) -> None:
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
    fixture.config = replace(fixture.config, configuration_digest=digest(policy))
    fixture.source = services.reconfigure_source(fixture.source.pk, fixture.config, fixture.admin)
    SecuritySyncState.objects.filter(source=fixture.source).update(
        last_published_generation=fixture.source.generation, outcome="ok"
    )
    fixture.target = services.enroll_source(
        replace(fixture.config, hostname="other-portal.example.test", installation_id=uuid4()), fixture.admin
    )
    state = SecuritySyncState.objects.get(source=fixture.source)
    SecuritySyncState.objects.filter(source=fixture.target).update(
        health=state.health, last_decision_sync_at=fixture.now, last_published_generation=1, outcome="ok"
    )
    fixture.proof = {
        "schema": 1,
        "installation_id": str(fixture.source.installation_id),
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
    fixture.decision = SecurityDecision.objects.create(
        source=fixture.source,
        remote_id=1,
        source_created_at=fixture.now,
        expires_at=fixture.now + timedelta(hours=4),
        scenario="crowdsecurity/http-cve-2021-41773",
        type="ban",
        scope="ip",
        value="198.51.100.8",
        origin="crowdsec",
        address_family=bounds.address_family,
        network_start=bounds.network_start,
        network_end=bounds.network_end,
    )


def approve_replication(fixture: ActionFixture) -> SecurityCoverageApproval:
    return replication.approve_coverage(
        actor=fixture.admin,
        reason="Reviewed real ingress native qualification",
        source_id=fixture.source.pk,
        scenarios=[fixture.decision.scenario],
        evidence_digest=digest(fixture.proof),
        native_evidence=fixture.proof,
    )


def prepare_node(
    fixture: ActionFixture,
) -> tuple[SecuritySource, VirtualminServer, NodeSecurityReview, dict[str, object]]:
    public = fixture.key.with_suffix(".pub")
    public.write_text(OPERATOR_KEY)
    configured = fixture.settings(PRAHO_CROWDSEC_SSH_PUBLIC_KEY_PATH=str(public))
    configured.enable()
    fixture.addCleanup(configured.disable)
    policy = {
        "schema": 1,
        "host_kind": "node",
        "simulation": False,
        "protected_cidrs": ["127.0.0.0/8"],
        "artifact_lock_sha256": "a" * 64,
        "bouncer_binary_sha256": "b" * 64,
        "managed_files": {
            "/etc/crowdsec/acquis.yaml": sha256(replication.NODE_JOURNAL_ACQUISITION.encode()).hexdigest()
        },
    }
    server = VirtualminServer.objects.create(hostname="admin-node.example.test", api_username="praho-api")
    select_security_profile(server, CROWDSEC_PROFILE, fixture.admin, configuration_digest=digest(policy))
    config = replace(
        fixture.config,
        kind="node",
        hostname=server.hostname,
        virtualmin_server_id=server.pk,
        installation_id=uuid4(),
        configuration_digest=digest(policy),
    )
    source = services.enroll_source(config, fixture.admin)
    state = SecuritySyncState.objects.get(source=fixture.source)
    SecuritySyncState.objects.filter(source=source).update(
        health=state.health, last_decision_sync_at=fixture.now, last_published_generation=1, outcome="ok"
    )
    server.refresh_from_db()
    evidence = node_policy_evidence()
    evidence["identity"] = connection_identity(server)
    evidence["services"] += [
        "PRAHO_CROWDSEC_CONFIG "
        + json.dumps(
            {
                "configuration_digest": digest(policy),
                "configuration_sha256": "f" * 64,
                "installation_id": str(source.installation_id),
                "root_owned": True,
            }
        ),
        "PRAHO_CROWDSEC_FILE "
        + json.dumps(
            {
                "path": "/etc/crowdsec/acquis.yaml",
                "sha256": policy["managed_files"]["/etc/crowdsec/acquis.yaml"],
                "root_owned": True,
            }
        ),
    ]
    review = NodeSecurityReview.objects.create(
        server=server,
        server_uuid=server.pk,
        policy_version=CROWDSEC_PROFILE,
        identity=evidence["identity"],
        digest=_evidence_digest(evidence, policy_version=CROWDSEC_PROFILE),
        evidence=evidence,
    )
    server.security_state, server.verified_security_review, server.current_security_review = (
        "verified_web",
        review,
        review,
    )
    server.save(update_fields=["security_state", "verified_security_review", "current_security_review"])
    proof = {
        "schema": 1,
        "installation_id": str(source.installation_id),
        "policy": policy,
        "acquisition_sha256": policy["managed_files"]["/etc/crowdsec/acquis.yaml"],
        "administrative_ssh": True,
        "ssh_journal_unit": "ssh.service",
        "ssh_listener_port": 9876,
        "http_listener_port": 443,
        "portal_http_qualified": False,
        "qualification_sha256": "e" * 64,
    }
    return source, server, review, proof
