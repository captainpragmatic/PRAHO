"""Explicit node-global handover; uncertainty retains the operation exclusion."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.infrastructure.node_maintenance_gate import (
    competing_operation_refusal,
    maintenance_refusal,
    node_configuration_refusal,
)
from apps.infrastructure.permissions import can_deploy_nodes

from .hosting_node_policy import (
    POLICY_VERSION,
    evidence_digest,
    notification_handover_refusal,
    verify_notification_evidence,
    verify_quota_evidence,
    verify_quota_inventory,
)
from .hosting_node_policy_models import NodeHostingExecution, NodeHostingPolicy, NodeHostingReview
from .virtualmin_models import VirtualminServer
from .virtualmin_security import MAX_REASON_LENGTH, connection_identity

if TYPE_CHECKING:
    from apps.users.models import User

_TRANSPORT_TOKEN: ContextVar[str | None] = ContextVar("hosting_node_transport_token", default=None)
MAX_OPERATOR_EMAILS = 25


def normalized_operator_emails(addresses: list[str] | None) -> list[str]:
    if addresses is None:
        return []
    if not isinstance(addresses, list) or len(addresses) > MAX_OPERATOR_EMAILS:
        raise ValidationError(_("Provide at most 25 explicit operator alert recipients."))
    result = set()
    for address in addresses:
        if not isinstance(address, str):
            raise ValidationError(_("Operator alert recipients must be email addresses."))
        validate_email(address)
        result.add(address.lower())
    return sorted(result)


@contextmanager
def hosting_transport_scope(token: UUID) -> Iterator[None]:
    previous = _TRANSPORT_TOKEN.set(str(token))
    try:
        yield
    finally:
        _TRANSPORT_TOKEN.reset(previous)


def hosting_operation_refusal(server_id: UUID) -> str | None:
    if NodeHostingPolicy.objects.filter(server_id=server_id, operation__isnull=False).exists():
        return _("A native hosting-policy operation owns this node; reconcile it before other work.")
    return None


def hosting_transport_allowed(server: VirtualminServer, variables: dict[str, Any] | None = None) -> bool:  # noqa: PLR0911 -- Each reviewed operation has a separate closed request contract.
    policy = NodeHostingPolicy.objects.filter(server_id=server.pk).first()
    if policy is None or policy.operation is None:
        return not variables or variables.get("hosting_action") == "inspect"
    token = _TRANSPORT_TOKEN.get()
    run = NodeHostingExecution.objects.filter(
        pk=policy.operation, server_id=server.pk, status__in=("running", "attention")
    ).first()
    if token != str(policy.operation) or run is None or run.expected_identity != connection_identity(server):
        return False
    request = (variables or {}).get("hosting_request", {})
    if (
        not isinstance(request, dict)
        or request.get("token") != token
        or request.get("identity") != run.expected_identity
    ):
        return False
    if run.action == "handover_mail":
        return bool(
            set(request) == {"token", "identity", "operator_emails"}
            and (variables or {}).get("hosting_action") in {"handover", "fence"}
            and request["operator_emails"] == run.authority.get("operator_emails")
        )
    if run.action == "prepare_helpers":
        return bool(
            set(request) == {"token", "identity", "helper_bundle_digest", "files"}
            and (variables or {}).get("hosting_action") in {"prepare", "fence"}
            and request["helper_bundle_digest"] == run.review.evidence.get("helper_bundle_digest")
        )
    if run.action == "adopt_quota":
        return bool(
            set(request) == {"identity", "token"}
            and (variables or {}).get("hosting_action") in {"quota_policy", "quota_fence"}
        )
    if run.action == "requalify_quota":
        return bool(
            set(request) == {"identity", "token"}
            and (variables or {}).get("hosting_action") in {"requalify", "requalify_fence"}
        )
    return False


@transaction.atomic
def invalidate_observed_quota_identity(server: VirtualminServer, observed: dict[str, Any]) -> bool:
    """A fresh same-node reboot observation revokes current proof without changing tenant caps."""
    from .hosting_limit_models import ServiceHostingLimits  # noqa: PLC0415 -- canonical current verification

    locked = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=server.pk)
    policy = NodeHostingPolicy.objects.filter(server=locked).first()
    if policy is None or not policy.quota_adopted or policy.connection_identity != connection_identity(locked):
        return False
    previous = policy.quota_evidence
    if any(observed.get(key) != previous.get(key) for key in ("installation", "filesystem_uuid")):
        return False
    try:
        boot = observed.get("boot_id")
        if not isinstance(boot, str) or str(UUID(boot)) != boot or previous.get("boot_id") == boot:
            return False
    except ValueError:
        return False
    policy.quota_verified_at = None
    policy.save(update_fields=["quota_verified_at", "updated_at"])
    ServiceHostingLimits.objects.filter(service__virtualmin_account__server=locked).update(verified_at=None)
    return True


@transaction.atomic
def record_hosting_inspection(server: VirtualminServer, evidence: dict[str, Any]) -> NodeHostingReview:
    locked = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=server.pk)
    if evidence.get("identity") != connection_identity(locked):
        raise ValidationError(_("Node connection changed during inspection."))
    quota = evidence.get("quota")
    if isinstance(quota, dict):
        invalidate_observed_quota_identity(locked, quota)
    return NodeHostingReview.objects.create(
        server=locked,
        server_uuid=locked.pk,
        policy_version=POLICY_VERSION,
        identity=evidence["identity"],
        digest=evidence_digest(evidence),
        evidence=evidence,
    )


@transaction.atomic
def claim_hosting_operation(  # noqa: PLR0913 -- Keep explicit actor/action/reason and separately bound operator authority.
    review: NodeHostingReview,
    current: dict[str, Any],
    actor: User,
    action: str,
    reason: str,
    *,
    operator_emails: list[str] | None = None,
) -> NodeHostingExecution:
    from .hosting_limit_execution import quota_operation_refusal  # noqa: PLC0415 -- shared active quota claims

    if not actor.is_active or not can_deploy_nodes(actor):
        raise PermissionDenied(_("Deployment permission is required."))
    if (
        action not in {"adopt_quota", "requalify_quota", "handover_mail", "prepare_helpers"}
        or not reason.strip()
        or len(reason) > MAX_REASON_LENGTH
    ):
        raise ValidationError(_("Choose a supported action and record an operator reason."))
    stored = NodeHostingReview.objects.get(pk=review.pk)
    if stored.server_id is None:
        raise ValidationError(_("The inspected node has been removed."))
    server = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=stored.server_id)
    if action == "adopt_quota" and (server.is_draining or server.status != "active"):
        raise ValidationError(_("Activate the node and finish draining before changing hosting policy."))
    refusal = (
        (maintenance_refusal(server.pk) or node_configuration_refusal(server.pk))
        if action == "requalify_quota"
        else (competing_operation_refusal(server.pk) or quota_operation_refusal(server.pk))
    )
    if refusal:
        raise ValidationError(refusal)
    if action == "handover_mail" and (refusal := notification_handover_refusal(server)):
        raise ValidationError(refusal)
    policy, _created = NodeHostingPolicy.objects.get_or_create(server=server)
    if policy.operation:
        raise ValidationError(_("Reconcile the existing hosting-policy attempt first."))
    if (
        stored.identity != connection_identity(server)
        or stored.policy_version != POLICY_VERSION
        or stored.digest != evidence_digest(stored.evidence)
        or stored.digest != evidence_digest(current)
    ):
        raise ValidationError(_("Native inventory changed; inspect and review it again."))
    if action in {"adopt_quota", "requalify_quota"}:
        verify_quota_inventory(current.get("quota", {}), stored.identity)
    if action == "requalify_quota":
        quota = current["quota"]
        if (
            not policy.quota_adopted
            or policy.connection_identity != stored.identity
            or not quota["requalification_required"]
            or any(
                quota.get(key) != policy.quota_evidence.get(key)
                for key in ("installation", "filesystem_uuid", "acceptance_id")
            )
        ):
            raise ValidationError(
                _(
                    "Isolated requalification requires the same previously adopted installation and filesystem after reboot."
                )
            )
    run = NodeHostingExecution.objects.create(
        server=server,
        server_uuid=server.pk,
        review=stored,
        actor=actor,
        reason=reason.strip(),
        action=action,
        expected_identity=stored.identity,
        authority={"operator_emails": normalized_operator_emails(operator_emails)},
    )
    policy.operation = run.pk
    policy.save(update_fields=["operation", "updated_at"])
    return run


@transaction.atomic
def complete_hosting_operation(run_id: UUID, evidence: dict[str, Any]) -> NodeHostingReview:
    hint = NodeHostingExecution.objects.get(pk=run_id)
    if hint.server_id is None:
        raise ValidationError(_("The node has been removed."))
    server = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=hint.server_id)
    policy = NodeHostingPolicy.objects.get(server=server)
    run = NodeHostingExecution.objects.select_for_update(of=("self",)).get(pk=run_id)
    if (
        policy.operation != run.pk
        or run.status not in {"running", "attention"}
        or run.expected_identity != connection_identity(server)
    ):
        raise ValidationError(_("Node hosting-policy ownership changed."))
    if evidence.get("identity") != run.expected_identity:
        raise ValidationError(_("Native receipt no longer matches the inspected node."))
    if run.action in {"adopt_quota", "requalify_quota"}:
        if evidence.get("fenced_token") != str(run.pk):
            raise ValidationError(_("Fence the native resource-policy token before completing managed quota adoption."))
        quota = verify_quota_evidence(evidence.get("quota", {}), run.expected_identity)
        reviewed = run.review.evidence.get("quota", {})
        if any(
            quota.get(key) != reviewed.get(key)
            for key in ("installation", "filesystem_uuid", "boot_id", "acceptance_id")
        ):
            raise ValidationError(
                _("The native qualification differs from the reviewed installation, filesystem or boot.")
            )
        policy.quota_adopted, policy.quota_evidence, policy.quota_verified_at = True, quota, timezone.now()
    elif run.action == "handover_mail":
        if refusal := notification_handover_refusal(server):
            raise ValidationError(refusal)
        if evidence.get("fenced_token") != str(run.pk):
            raise ValidationError(_("Fence the native handover token before releasing uncertain ownership."))
        mail = verify_notification_evidence(evidence.get("notifications", {}), run.expected_identity)
        policy.notification_owner, policy.notification_evidence = "platform", mail
        policy.notifications_verified_at = timezone.now()
    elif evidence.get("fenced_token") != str(run.pk) or evidence.get("helper_bundle_digest") != run.review.evidence.get(
        "helper_bundle_digest"
    ):
        raise ValidationError(_("The prepared helper bundle must match its reviewed and fenced installation."))
    proof = NodeHostingReview.objects.create(
        server=server,
        server_uuid=server.pk,
        policy_version=POLICY_VERSION,
        identity=run.expected_identity,
        digest=evidence_digest(evidence),
        evidence=evidence,
    )
    run.verification = proof
    run.mark_verified()
    run.save(update_fields=["verification", "status", "updated_at"])
    policy.connection_identity, policy.policy_version, policy.operation = run.expected_identity, POLICY_VERSION, None
    policy.revision += 1
    policy.save()
    return proof


@transaction.atomic
def park_hosting_operation(run_id: UUID) -> None:
    run = NodeHostingExecution.objects.select_for_update(of=("self",)).get(pk=run_id)
    if run.status == "running":
        run.require_attention()
        run.save(update_fields=["status", "updated_at"])
