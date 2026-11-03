"""Queue leaves re-read operator authority and native inventory before claiming."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.core.exceptions import PermissionDenied, ValidationError
from django.utils.translation import gettext as _

from apps.infrastructure.permissions import can_deploy_nodes

from .hosting_node_bundle import helper_bundle
from .hosting_node_execution import (
    claim_hosting_operation,
    complete_hosting_operation,
    hosting_transport_scope,
    park_hosting_operation,
    record_hosting_inspection,
)
from .hosting_node_policy import evidence_digest
from .hosting_node_policy_models import NodeHostingExecution, NodeHostingPolicy, NodeHostingReview
from .hosting_node_transport import run_helper_operation, run_node_operation
from .virtualmin_models import VirtualminServer
from .virtualmin_security import connection_identity

if TYPE_CHECKING:
    from apps.users.models import User


def collect_hosting_inspection(server: VirtualminServer) -> dict[str, Any]:
    identity = connection_identity(server)
    evidence = run_node_operation(server, "inspect", {"identity": identity})
    fresh = VirtualminServer.objects.get(pk=server.pk)
    if evidence.get("identity") != identity or connection_identity(fresh) != identity:
        raise ValidationError(_("Node identity changed during inspection; inspect again."))
    evidence_digest(evidence)
    return evidence


def _claim_reviewed_run(
    server: VirtualminServer, actor: User, action: str, payload: dict[str, Any]
) -> tuple[NodeHostingExecution, dict[str, Any]]:
    if action == "reconcile":
        policy = NodeHostingPolicy.objects.get(server=server)
        if policy.operation is None:
            raise ValidationError(_("There is no held hosting-policy operation."))
        return NodeHostingExecution.objects.get(pk=policy.operation, server=server, status="attention"), {}
    if action == "prepare_helpers":
        bundle = helper_bundle()
        if payload.get("helper_bundle_digest") != bundle["helper_bundle_digest"]:
            raise ValidationError(_("The inspection helper release changed; review and approve it again."))
        current = {"identity": connection_identity(server), "helper_bundle_digest": bundle["helper_bundle_digest"]}
        review = record_hosting_inspection(server, current)
    else:
        current = collect_hosting_inspection(server)
        review_id = payload.get("review_id")
        if not isinstance(review_id, str) or not review_id:
            raise ValidationError(_("Inspect the node and choose its reviewed inventory before this action."))
        review = NodeHostingReview.objects.get(pk=review_id, server=server)
    run = claim_hosting_operation(
        review, current, actor, action, payload.get("reason", ""), operator_emails=payload.get("operator_emails")
    )
    return run, current


def _execute_reviewed_run(
    server: VirtualminServer, run: NodeHostingExecution, current: dict[str, Any], *, reconcile: bool
) -> dict[str, Any]:
    if run.action == "prepare_helpers":
        bundle = helper_bundle()
        if bundle["helper_bundle_digest"] != run.review.evidence["helper_bundle_digest"]:
            raise ValidationError(_("Reconcile this attempt with its originally reviewed helper release."))
        with hosting_transport_scope(run.pk):
            return run_helper_operation(
                server,
                "fence" if reconcile else "prepare",
                {"identity": run.expected_identity, "token": str(run.pk), **bundle},
            )
    if run.action == "handover_mail":
        with hosting_transport_scope(run.pk):
            return run_node_operation(
                server,
                "fence" if reconcile else "handover",
                {
                    "identity": run.expected_identity,
                    "token": str(run.pk),
                    "operator_emails": run.authority["operator_emails"],
                },
            )
    if run.action == "adopt_quota":
        with hosting_transport_scope(run.pk):
            return run_node_operation(
                server,
                "quota_fence" if reconcile else "quota_policy",
                {"identity": run.expected_identity, "token": str(run.pk)},
            )
    if run.action == "requalify_quota":
        with hosting_transport_scope(run.pk):
            return run_node_operation(
                server,
                "requalify_fence" if reconcile else "requalify",
                {"identity": run.expected_identity, "token": str(run.pk)},
            )
    return collect_hosting_inspection(server) if reconcile else current


def review_node_hosting(
    server_id: str, actor_id: str, action: str, payload: dict[str, Any] | None = None
) -> dict[str, str]:
    from apps.users.models import User  # noqa: PLC0415 -- Cross-app authority resolved at task execution.

    actor = User.objects.get(pk=actor_id)
    if not actor.is_active or not can_deploy_nodes(actor):
        raise PermissionDenied(_("Deployment permission is required."))
    if action not in {"inspect", "adopt_quota", "requalify_quota", "handover_mail", "prepare_helpers", "reconcile"}:
        raise ValidationError(_("Unsupported native hosting policy action."))
    server = VirtualminServer.objects.get(pk=server_id)
    run = None
    try:
        if action == "inspect":
            proof = record_hosting_inspection(server, collect_hosting_inspection(server))
            return {"outcome": "inspected", "review_id": str(proof.pk)}
        run, current = _claim_reviewed_run(server, actor, action, payload or {})
        evidence = _execute_reviewed_run(server, run, current, reconcile=action == "reconcile")
        verified = complete_hosting_operation(run.pk, evidence)
        return {"outcome": "verified", "review_id": str(verified.pk)}
    except (
        ValidationError,
        NodeHostingReview.DoesNotExist,
        NodeHostingExecution.DoesNotExist,
        NodeHostingPolicy.DoesNotExist,
    ) as error:
        message = (
            "; ".join(error.messages)
            if isinstance(error, ValidationError)
            else str(_("Inspect the held operation before reconciliation."))
        )
        return {"outcome": "attention", "message": message}
    finally:
        if run is not None:
            park_hosting_operation(run.pk)
