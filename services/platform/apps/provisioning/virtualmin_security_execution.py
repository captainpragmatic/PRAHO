"""Claim once before remote mutation; unknown outcomes retain their exclusion."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, cast
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from apps.infrastructure.ansible_service import AnsibleService, node_admin_allowed_cidrs
from apps.infrastructure.permissions import can_deploy_nodes

from .virtualmin_models import VirtualminServer
from .virtualmin_security import (
    MAX_REASON_LENGTH,
    POLICY_VERSION,
    _evidence_digest,
    connection_identity,
    validate_decision,
)
from .virtualmin_security_models import NodeSecurityDecision, NodeSecurityExecution, NodeSecurityReview
from .virtualmin_security_policy import verify_evidence, verify_network_ingress

if TYPE_CHECKING:
    from apps.users.models import User

_TRANSPORT_EXECUTION: ContextVar[str | None] = ContextVar("node_security_transport_execution", default=None)
_TRANSPORT_POLICY: ContextVar[dict[str, object] | None] = ContextVar("node_security_transport_policy", default=None)


def operator_key_fingerprints(keys: tuple[str, ...]) -> list[str]:
    return [
        "Approved operator SSH key: SHA256:"
        + base64.b64encode(hashlib.sha256(base64.b64decode(key.split()[1], validate=True)).digest())
        .decode()
        .rstrip("=")
        for key in keys
    ]


def reviewed_transport_policy(server: VirtualminServer, token: str) -> dict[str, object]:
    """Freeze the exact reviewed inputs, so config changes during a step cannot widen access."""
    if not owns_hardening(server, token):
        raise ValidationError(_("Hardening operation ownership changed."))
    execution = NodeSecurityExecution.objects.select_related("decision__review").get(pk=token)
    proposals = cast("list[str]", execution.decision.review.evidence["proposed_changes"])
    cidrs = sorted(node_admin_allowed_cidrs())
    try:
        keys = AnsibleService.operator_public_keys()
    except (OSError, ValueError) as error:
        raise ValidationError(_("The reviewed operator SSH key bundle is unavailable or invalid.")) from error
    networks = [line for line in proposals if line.startswith("Administrative networks: ")]
    recorded_keys = sorted(line for line in proposals if line.startswith("Approved operator SSH key: "))
    if (
        not cidrs
        or not keys
        or networks != ["Administrative networks: " + ", ".join(cidrs)]
        or sorted(operator_key_fingerprints(keys)) != recorded_keys
    ):
        raise ValidationError(_("Administrative networks or operator keys differ from the reviewed preview."))
    return {"node_admin_allowed_cidrs": cidrs, "ssh_allowed_cidrs": cidrs, "ssh_operator_public_keys": list(keys)}


def frozen_transport_policy() -> dict[str, object] | None:
    policy = _TRANSPORT_POLICY.get()
    return dict(policy) if policy is not None else None


@contextmanager
def hardening_transport_scope(token: str, policy: dict[str, object] | None = None) -> Iterator[None]:
    """Carry authority into recursive managed SSH preflight without ambient global state."""
    previous = _TRANSPORT_EXECUTION.set(token)
    previous_policy = _TRANSPORT_POLICY.set(policy)
    try:
        yield
    finally:
        _TRANSPORT_EXECUTION.reset(previous)
        _TRANSPORT_POLICY.reset(previous_policy)


def transport_mutation_allowed(server: VirtualminServer) -> bool:
    current = VirtualminServer.objects.get(pk=server.pk)
    if current.security_operation is None:
        return True
    token = _TRANSPORT_EXECUTION.get()
    return token is not None and owns_hardening(current, token)


def owns_hardening(server: VirtualminServer, token: str) -> bool:
    try:
        parsed = UUID(token)
    except (ValueError, TypeError):
        return False
    current = VirtualminServer.objects.filter(pk=server.pk, security_operation=parsed).first()
    return (
        current is not None
        and NodeSecurityExecution.objects.filter(
            pk=parsed,
            server=server,
            server_uuid=server.pk,
            status="running",
            decision__action="apply_hardening",
            expected_identity=connection_identity(current),
        ).exists()
    )


@transaction.atomic
def claim_hardening(
    review: NodeSecurityReview, evidence: dict[str, object], actor: User, reason: str
) -> NodeSecurityExecution:
    if not actor.is_active or not can_deploy_nodes(actor):
        raise PermissionDenied(_("Deployment permission is required."))
    if not reason.strip() or len(reason) > MAX_REASON_LENGTH:
        raise ValidationError(_("Describe service evacuation and accept the operational impact."))
    stored = NodeSecurityReview.objects.get(pk=review.pk)
    if stored.server_id is None:
        raise ValidationError(_("The inspected node has been removed."))
    server = VirtualminServer.objects.select_for_update().get(pk=stored.server_id)
    validate_decision(server, stored, evidence)
    # Read-only qualification precedes decisions, operation exclusion and enrollment.
    verify_network_ingress(cast("list[str]", evidence["firewall"]))
    from .component_migration_models import retained_source_refusal  # noqa: PLC0415 -- node responsibility boundary

    retained = retained_source_refusal(server.pk)
    if retained:
        raise ValidationError(retained)
    if server.is_draining or server.status != "active":
        raise ValidationError(_("Resolve the node lifecycle operation before hardening."))
    deployment = getattr(server, "node_deployment", None)
    if deployment is not None and deployment.status != "completed":
        raise ValidationError(_("Resolve the managed deployment operation before hardening."))
    if evidence["versions"] != {"webmin": "2.670", "virtualmin": "8.3.0"}:
        raise ValidationError(_("Qualify the installed native versions before applying this policy."))
    from .virtualmin_drain_service import server_has_active_migration  # noqa: PLC0415 -- avoids app cycle

    if (
        server_has_active_migration(server)
        or server.provisioning_jobs.filter(status__in=["pending", "running", "attention"]).exists()
    ):
        raise ValidationError(_("Resolve active node work before changing access and services."))
    decision = NodeSecurityDecision.objects.create(
        review=stored, actor=actor, action="apply_hardening", reason=reason.strip()
    )
    execution = NodeSecurityExecution.objects.create(
        server=server, server_uuid=server.pk, decision=decision, expected_identity=stored.identity
    )
    server.security_operation = execution.pk
    server.security_state = "unreviewed"
    server.verified_security_review = None
    server.save(update_fields=["security_operation", "security_state", "verified_security_review", "updated_at"])
    return execution


@transaction.atomic
def park_hardening(token: UUID) -> None:
    execution = NodeSecurityExecution.objects.filter(pk=token).first()
    if execution is None or execution.server_id is None:
        raise ValidationError(_("Hardening operation no longer exists."))
    server = VirtualminServer.objects.select_for_update().get(pk=execution.server_id)
    if server.security_operation != token or execution.status != "running":
        raise ValidationError(_("Hardening operation ownership changed."))
    # fsm-bypass: metadata CharField; server row lock and token fence above.
    execution.status = "needs_review"
    execution.save(update_fields=["status", "updated_at"])


def complete_hardening(
    token: UUID,
    evidence: dict[str, object],
    *,
    actor: User | None = None,
    reason: str = "Native policy and dedicated API verified",
) -> NodeSecurityReview:
    """Only fresh full-policy evidence plus real dedicated API authentication can release exclusion."""
    from .virtualmin_gateway import VirtualminConfig, VirtualminGateway  # noqa: PLC0415 -- app boundary

    execution = NodeSecurityExecution.objects.get(pk=token)
    actor = actor or execution.decision.actor
    if not actor.is_active or not can_deploy_nodes(actor):
        raise PermissionDenied(_("Deployment permission is required."))
    if not reason.strip() or len(reason) > MAX_REASON_LENGTH:
        raise ValidationError(_("Describe the verification and operator responsibility."))
    if execution.server_id is None:
        raise ValidationError(_("The node has been removed."))
    server = VirtualminServer.objects.get(pk=execution.server_id)
    if server.security_operation != token or execution.status not in {"running", "needs_review"}:
        raise ValidationError(_("Hardening operation ownership changed."))
    proposals = cast("list[str]", execution.decision.review.evidence["proposed_changes"])
    cidrs = sorted(node_admin_allowed_cidrs())
    if [line for line in proposals if line.startswith("Administrative networks: ")] != [
        "Administrative networks: " + ", ".join(cidrs)
    ]:
        raise ValidationError(_("Administrative networks differ from the approved preview."))
    fingerprints = [
        line.removeprefix("Approved operator SSH key: ")
        for line in proposals
        if line.startswith("Approved operator SSH key: ")
    ]
    verify_evidence(evidence, server.api_username, cidrs, expected_operator_fingerprints=fingerprints)
    gateway = VirtualminGateway(VirtualminConfig(server=server))
    credentials = gateway._get_credentials(reason="Verify dedicated identity after node hardening")
    if credentials.is_err() or credentials.unwrap()[0] != server.api_username:
        raise ValidationError(_("The durable API credential does not match the reviewed dedicated identity."))
    api = gateway.test_connection()
    if api.is_err() or api.unwrap().get("healthy") is not True:
        raise ValidationError(_("The dedicated API identity did not authenticate after hardening."))
    with transaction.atomic():
        server = VirtualminServer.objects.select_for_update().get(pk=server.pk)
        if server.security_operation != token or evidence["identity"] != connection_identity(server):
            raise ValidationError(_("Node connection or operation changed during verification."))
        verification = NodeSecurityReview.objects.create(
            server=server,
            server_uuid=server.pk,
            policy_version=POLICY_VERSION,
            identity=cast("str", evidence["identity"]),
            digest=_evidence_digest(evidence),
            evidence=evidence,
        )
        NodeSecurityDecision.objects.create(
            review=verification, actor=actor, action="verify_policy", reason=reason.strip()
        )
        execution.verification = verification
        # fsm-bypass: metadata CharField; server row lock and token fence above.
        execution.status = "verified"
        execution.save(update_fields=["verification", "status", "updated_at"])
        server.current_security_review = verification
        server.verified_security_review = verification
        server.security_state = "verified_web"
        server.security_operation = None
        server.save(
            update_fields=[
                "current_security_review",
                "verified_security_review",
                "security_state",
                "security_operation",
                "updated_at",
            ]
        )
        return verification
