"""Only explicitly qualified native hostile detections can produce nonrenewable replicas."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, timedelta
from typing import TYPE_CHECKING, cast
from uuid import UUID, uuid4

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .action_repos import lock_sources
from .action_services import (
    NODE_BAN_SECONDS,
    PORTAL_BAN_SECONDS,
    audit,
    authorize,
    canonical_address,
    reason_text,
    request_record,
    require_create,
    target_record,
)
from .action_transport import digest
from .models import (
    SecurityActionRequest,
    SecurityCoverageApproval,
    SecurityDecision,
    SecurityDecisionSuppression,
    SecurityReplication,
    SecurityReplicationScan,
    SecuritySource,
)
from .transport import capture_connection

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_security_models import NodeSecurityReview
    from apps.users.models import User

SSH_SCENARIOS = frozenset(
    {
        "crowdsecurity/ssh-bf",
        "crowdsecurity/ssh-bf_user-enum",
        "crowdsecurity/ssh-slow-bf",
        "crowdsecurity/ssh-slow-bf_user-enum",
        "crowdsecurity/ssh-cve-2024-6387",
    }
)
HTTP_SCENARIOS = frozenset({"crowdsecurity/http-cve-2021-41773", "crowdsecurity/http-cve-2021-42013"})
SCENARIOS = SSH_SCENARIOS | HTTP_SCENARIOS
ACQUISITION_PATH = "/etc/crowdsec/acquis.yaml"
MAX_PROOF_BYTES = 65536
MAX_MANAGED_FILES = 64
MAX_MANAGED_PATH = 256
ADMIN_SSH_PORT = 9876
HTTP_PORT = 443
_SSH_JOURNAL = "source: journalctl\njournalctl_filter:\n  - _SYSTEMD_UNIT=ssh.service\nlabels:\n  type: syslog\n"
_SSH_FILE = "filenames:\n  - /var/log/auth.log\nlabels:\n  type: syslog\n"
_NODE_WEB = "---\nfilenames:\n  - /var/log/virtualmin/*_access_log\nlabels:\n  type: apache2\n---\nfilenames:\n  - /var/webmin/webmin.log\nlabels:\n  type: webmin\n"
_PORTAL_WEB = "---\nfilenames:\n  - /var/log/caddy/portal-access.log\nlabels:\n  type: caddy\n---\nfilenames:\n  - /var/log/praho/portal/portal-auth.jsonl\nlabels:\n  type: praho_portal_auth\n"
NODE_JOURNAL_ACQUISITION = _SSH_JOURNAL + _NODE_WEB
NODE_FILE_ACQUISITION = _SSH_FILE + _NODE_WEB
PORTAL_JOURNAL_ACQUISITION = _SSH_JOURNAL + _PORTAL_WEB
PORTAL_FILE_ACQUISITION = _SSH_FILE + _PORTAL_WEB
_PROOF_KEYS = frozenset(
    {
        "schema",
        "installation_id",
        "policy",
        "acquisition_sha256",
        "administrative_ssh",
        "ssh_journal_unit",
        "ssh_listener_port",
        "http_listener_port",
        "portal_http_qualified",
        "qualification_sha256",
    }
)
_SSH_PROOF_KEYS = frozenset({"ssh_exclusive_administrative", "customer_sftp_excluded"})
_POLICY_KEYS = frozenset(
    {
        "schema",
        "host_kind",
        "simulation",
        "protected_cidrs",
        "artifact_lock_sha256",
        "bouncer_binary_sha256",
        "managed_files",
    }
)


def _hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _native_review(source: SecuritySource) -> NodeSecurityReview | None:
    if source.kind != "node":
        return None
    from apps.provisioning.virtualmin_node_capability import destination_refusal  # noqa: PLC0415 -- native admission
    from apps.provisioning.virtualmin_security import _evidence_digest  # noqa: PLC0415 -- immutable native evidence

    server = source.virtualmin_server
    review = server.verified_security_review if server else None
    if (
        server is None
        or review is None
        or destination_refusal(server) is not None
        or review.identity != source.virtualmin_identity
        or review.digest != _evidence_digest(review.evidence, policy_version=review.policy_version)
    ):
        raise ValidationError(_("Current native CrowdSec node qualification is required for sharing."))
    return review


def _proof(
    source: SecuritySource, scenarios: list[str], evidence: dict[str, object], checksum: str, administrative_ssh: bool
) -> None:
    try:
        if (
            len(json.dumps(evidence).encode()) > MAX_PROOF_BYTES
            or not _PROOF_KEYS <= set(evidence) <= _PROOF_KEYS | _SSH_PROOF_KEYS
            or (set(evidence) & _SSH_PROOF_KEYS not in (set(), _SSH_PROOF_KEYS))
            or not _hex(checksum)
            or digest(evidence) != checksum
            or type(evidence["schema"]) is not int
            or evidence["schema"] != 1
            or type(evidence["administrative_ssh"]) is not bool
            or type(evidence["portal_http_qualified"]) is not bool
            or evidence["installation_id"] != str(source.installation_id)
            or not _hex(evidence["qualification_sha256"])
        ):
            raise ValueError("Unbound native evidence")
        policy = cast("dict[str, object]", evidence["policy"])
        if (
            not isinstance(policy, dict)
            or set(policy) != _POLICY_KEYS
            or type(policy["schema"]) is not int
            or policy["schema"] != 1
            or policy["host_kind"] != source.kind
            or policy["simulation"] is not False
            or digest(policy) != source.configuration_digest
        ):
            raise ValueError("Unbound policy")
        files = policy["managed_files"]
        if (
            not isinstance(files, dict)
            or not 1 <= len(files) <= MAX_MANAGED_FILES
            or files.get(ACQUISITION_PATH) != evidence["acquisition_sha256"]
            or any(
                not isinstance(path, str) or len(path) > MAX_MANAGED_PATH or not _hex(sha)
                for path, sha in files.items()
            )
        ):
            raise ValueError("Unbound acquisition")
        candidates = (
            (NODE_FILE_ACQUISITION, NODE_JOURNAL_ACQUISITION)
            if source.kind == "node"
            else (PORTAL_FILE_ACQUISITION, PORTAL_JOURNAL_ACQUISITION)
        )
        if evidence["acquisition_sha256"] not in {
            hashlib.sha256(candidate.encode()).hexdigest() for candidate in candidates
        }:
            raise ValueError("Unknown acquisition bytes")
        if SSH_SCENARIOS.intersection(scenarios) and not (
            source.kind == "node"
            and administrative_ssh is True
            and evidence["administrative_ssh"] is True
            and evidence.get("ssh_exclusive_administrative") is True
            and evidence.get("customer_sftp_excluded") is True
            and evidence["ssh_journal_unit"] == "ssh.service"
            and type(evidence["ssh_listener_port"]) is int
            and evidence["ssh_listener_port"] == ADMIN_SSH_PORT
            and evidence["acquisition_sha256"] == hashlib.sha256(NODE_JOURNAL_ACQUISITION.encode()).hexdigest()
        ):
            raise ValueError("Administrative SSH provenance missing")
        if HTTP_SCENARIOS.intersection(scenarios) and (
            type(evidence["http_listener_port"]) is not int
            or evidence["http_listener_port"] != HTTP_PORT
            or (source.kind == "portal" and evidence["portal_http_qualified"] is not True)
        ):
            raise ValueError("HTTP ingress qualification missing")
        review = _native_review(source)
        if review is not None:
            configs = [
                json.loads(row.split(" ", 1)[1])
                for row in review.evidence["services"]
                if row.startswith("PRAHO_CROWDSEC_CONFIG ")
            ]
            if (
                len(configs) != 1
                or set(configs[0]) != {"configuration_digest", "configuration_sha256", "installation_id", "root_owned"}
                or configs[0]["installation_id"] != str(source.installation_id)
                or configs[0]["configuration_digest"] != source.configuration_digest
                or configs[0]["root_owned"] is not True
                or not _hex(configs[0]["configuration_sha256"])
            ):
                raise ValueError("Native physical installation mismatch")
            rows = [
                json.loads(row.split(" ", 1)[1])
                for row in review.evidence["services"]
                if row.startswith("PRAHO_CROWDSEC_FILE ")
            ]
            if not any(
                row.get("path") == ACQUISITION_PATH
                and row.get("sha256") == evidence["acquisition_sha256"]
                and row.get("root_owned") is True
                for row in rows
            ):
                raise ValueError("Native acquisition mismatch")
            if SSH_SCENARIOS.intersection(scenarios) and not any(
                line.startswith("tcp ") and line.split()[4].rsplit(":", 1)[1] == "9876"
                for line in review.evidence["listeners"]
            ):
                raise ValueError("Administrative listener missing")
    except (ValueError, KeyError, TypeError, IndexError, RecursionError) as error:
        raise ValidationError(
            _("Explicit native detection coverage proof is incomplete or does not match this enrollment.")
        ) from error


@transaction.atomic
def approve_coverage(  # noqa: PLR0913 -- operator assertion and independent native evidence stay explicit.
    *,
    actor: User,
    reason: str,
    source_id: UUID,
    scenarios: list[str],
    evidence_digest: str,
    native_evidence: dict[str, object],
    administrative_ssh: bool = False,
) -> SecurityCoverageApproval:
    authorize(actor)
    reason = reason_text(reason)
    if not isinstance(scenarios, list) or not scenarios or not set(scenarios) <= SCENARIOS:
        raise ValidationError(_("Only exact pinned hostile scenario candidates can be approved."))
    source = lock_sources([source_id])[source_id]
    require_create(source)
    connection = capture_connection(source)
    _proof(source, scenarios, native_evidence, evidence_digest, administrative_ssh)
    review = _native_review(source)
    approval = SecurityCoverageApproval.objects.create(
        source=source,
        generation=source.generation,
        configuration_digest=source.configuration_digest,
        connection_identity=connection.identity,
        review=review,
        evidence_digest=evidence_digest,
        native_evidence=native_evidence,
        scenarios=sorted(set(scenarios)),
        actor=actor,
        reason=reason,
    )
    from apps.audit.services import AuditService  # noqa: PLC0415 -- explicit approval audit

    AuditService.log_simple_event(
        "configuration_changed",
        user=actor,
        content_object=approval,
        description="Approved qualified native CrowdSec detection coverage",
        new_values={
            "scenarios": approval.scenarios,
            "evidence_digest": evidence_digest,
            "generation": source.generation,
            "reason": reason,
        },
        metadata={"source_app": "security"},
    )
    return approval


@transaction.atomic
def withdraw_coverage(*, actor: User, reason: str, source_id: UUID) -> int:
    authorize(actor)
    reason = reason_text(reason)
    source = lock_sources([source_id])[source_id]
    count = source.coverage_approvals.filter(generation=source.generation, revoked_at__isnull=True).update(
        revoked_at=timezone.now(), updated_at=timezone.now()
    )
    if count:
        from apps.audit.services import AuditService  # noqa: PLC0415 -- explicit coverage withdrawal

        AuditService.log_simple_event(
            "configuration_changed",
            user=actor,
            content_object=source,
            description="Withdrew CrowdSec detection sharing coverage",
            new_values={"generation": source.generation, "approvals_withdrawn": count, "reason": reason},
            metadata={"source_app": "security"},
        )
    return count


def valid_origin(decision: SecurityDecision) -> bool:
    source = decision.source
    if (
        decision.origin != "crowdsec"
        or decision.type != "ban"
        or decision.simulated
        or decision.scenario not in SCENARIOS
        or decision.ended_at is not None
        or decision.expires_at <= timezone.now()
        or not source.sync_enabled
        or SecurityDecisionSuppression.objects.filter(
            source_id=decision.source_id, remote_id=decision.remote_id
        ).exists()
    ):
        return False
    try:
        canonical_address(decision.scope, decision.value)
        require_create(source)
        identity = capture_connection(source).identity
        review = _native_review(source)
        approvals = source.coverage_approvals.filter(
            generation=source.generation,
            configuration_digest=source.configuration_digest,
            connection_identity=identity,
            revoked_at__isnull=True,
            review=review,
        )
        for approval in approvals:
            if decision.scenario in approval.scenarios:
                _proof(
                    source,
                    approval.scenarios,
                    approval.native_evidence,
                    approval.evidence_digest,
                    approval.native_evidence.get("administrative_ssh") is True,
                )
                return True
    except ValidationError:
        return False
    return False


@transaction.atomic
def replicate_decision(decision_id: UUID) -> list[SecurityActionRequest]:
    if not getattr(settings, "PRAHO_CROWDSEC_REPLICATION_ENABLED", False) or not getattr(
        settings, "PRAHO_CROWDSEC_ACTIONS_ENABLED", False
    ):
        return []
    decision = SecurityDecision.objects.get(pk=decision_id)
    target_ids = list(
        SecuritySource.objects.filter(sync_enabled=True, retired_at__isnull=True)
        .exclude(pk=decision.source_id)
        .values_list("pk", flat=True)
    )
    sources = lock_sources([decision.source_id, *target_ids])
    SecurityReplicationScan.objects.update_or_create(decision=decision, defaults={"checked_at": timezone.now()})
    decision.source = sources[decision.source_id]
    if not valid_origin(decision):
        return []
    value = canonical_address(decision.scope, decision.value)
    results = []
    for source_id in target_ids:
        target_source = sources[source_id]
        if (
            target_source.installation_id == decision.source.installation_id
            or SecurityReplication.objects.filter(
                origin_installation_id=decision.source.installation_id,
                origin_remote_id=decision.remote_id,
                target_source=target_source,
            ).exists()
        ):
            continue
        try:
            require_create(target_source, {"value": value})
        except ValidationError:
            continue
        action, _created = request_record(
            "replica",
            uuid4(),
            {"decision": str(decision.pk), "target": str(source_id)},
            None,
            "Explicitly approved hostile native detection",
            decision,
        )
        expires = min(
            decision.expires_at,
            action.created_at
            + timedelta(seconds=PORTAL_BAN_SECONDS if target_source.kind == "portal" else NODE_BAN_SECONDS),
        )
        replica = SecurityReplication.objects.create(
            decision=decision,
            origin_installation_id=decision.source.installation_id,
            origin_remote_id=decision.remote_id,
            target_source=target_source,
            expires_at=expires,
        )
        payload = {
            "provenance_id": str(replica.provenance_id),
            "revision": 1,
            "kind": "replica",
            "scope": decision.scope,
            "value": value,
            "expires_at": expires.astimezone(UTC).isoformat(),
            "source": {
                "installation_id": str(decision.source.installation_id),
                "decision_id": decision.remote_id,
                "scenario": decision.scenario,
                "configuration_digest": decision.source.configuration_digest,
            },
        }
        replica.create_target = target_record(action, target_source, "ban_put", payload, expires_at=expires)
        replica.save(update_fields=["create_target", "updated_at"])
        audit(action)
        results.append(action)
    return results


def dispatch_replication() -> dict[str, int]:
    if not getattr(settings, "PRAHO_CROWDSEC_REPLICATION_ENABLED", False):
        return {"admitted": 0}
    decisions = (
        SecurityDecision.objects.filter(
            origin="crowdsec",
            type="ban",
            simulated=False,
            ended_at__isnull=True,
            expires_at__gt=timezone.now(),
            scenario__in=SCENARIOS,
        )
        .exclude(suppression__isnull=False)
        .order_by(F("replication_scan__checked_at").asc(nulls_first=True), "first_seen_at", "pk")
        .values_list("pk", flat=True)[:100]
    )
    return {"admitted": sum(len(replicate_decision(decision_id)) for decision_id in list(decisions))}
