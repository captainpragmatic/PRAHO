"""Read again at decision time; a displayed preview is never execution authority."""

import base64
import json
import re
from typing import cast

from django.core.exceptions import PermissionDenied, ValidationError
from django.utils.translation import gettext as _

from apps.infrastructure.ansible_service import AnsibleService, node_admin_allowed_cidrs, uncovered_platform_egress
from apps.infrastructure.permissions import can_deploy_nodes

from .virtualmin_models import VirtualminServer
from .virtualmin_security import MAX_EVIDENCE_BYTES, acknowledge_source, connection_identity, record_inspection
from .virtualmin_security_apply import apply_hardening, dedicated_username
from .virtualmin_security_execution import (
    claim_hardening,
    complete_hardening,
    operator_key_fingerprints,
    park_hardening,
)
from .virtualmin_security_models import NodeSecurityExecution, NodeSecurityReview
from .virtualmin_security_policy import network_preparation


def collect_inspection(server: VirtualminServer) -> dict[str, object]:
    identity = connection_identity(server)
    result = AnsibleService().run_server_playbook(
        server, "virtualmin_security_read.yml", {"security_identity": identity}, timeout_seconds=120
    )
    if result.is_err() or not result.unwrap().success:
        raise ValidationError(
            _("Security inspection failed. Check enrolled SSH access and installed inspection tools.")
        )
    matches = re.findall(r"PRAHO_SECURITY_INSPECTION=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    if len(matches) != 1 or len(matches[0]) > MAX_EVIDENCE_BYTES * 2:
        raise ValidationError(_("Node returned an incomplete or oversized inspection."))
    try:
        evidence = json.loads(base64.b64decode(matches[0], validate=True))
    except (ValueError, UnicodeError) as error:
        raise ValidationError(_("Node returned an invalid inspection.")) from error
    if not isinstance(evidence, dict) or evidence.get("identity") != identity:
        raise ValidationError(_("Inspection does not match the requested node identity."))
    proposals = evidence.get("proposed_changes")
    if not isinstance(proposals, list) or any(not isinstance(item, str) for item in proposals):
        raise ValidationError(_("Inspection lacks proposed changes."))
    proposals.append("Administrative networks: " + ", ".join(sorted(node_admin_allowed_cidrs())))
    if uncovered := uncovered_platform_egress():
        proposals.append(
            "Warning: Platform source addresses outside the administrative networks: "
            + ", ".join(uncovered)
            + ". The node firewall will drop Platform's connections from them."
        )
    proposals.append("Dedicated API login after conversion: " + dedicated_username(server))
    proposals.append(
        "Rotate the dedicated API password; preserve the separate root rescue login for local operator access."
    )
    proposals.extend(network_preparation(cast("list[str]", evidence.get("firewall", []))))
    try:
        operator_keys = AnsibleService.operator_public_keys()
    except (OSError, ValueError):
        proposals.append("Operator SSH key bundle is unavailable; prepare it before applying conversion.")
    else:
        proposals.extend(operator_key_fingerprints(operator_keys))
    server.refresh_from_db()
    if connection_identity(server) != identity:
        raise ValidationError(_("Node connection changed during inspection. Inspect it again."))
    return cast("dict[str, object]", evidence)


def review_node_security(
    server_id: str, actor_id: str, action: str, review_id: str = "", reason: str = ""
) -> dict[str, str]:
    from apps.users.models import User  # noqa: PLC0415 -- cross-app model boundary (ADR-0007)

    actor = User.objects.get(pk=actor_id)
    if not actor.is_active or not actor.is_staff_user:
        raise PermissionDenied(_("Staff access is required."))
    if action not in {"inspect", "acknowledge", "apply", "verify"}:
        raise ValidationError(_("Invalid security action."))
    if action != "inspect" and not can_deploy_nodes(actor):
        raise PermissionDenied(_("Deployment permission is required."))
    server = VirtualminServer.objects.get(pk=server_id)
    execution = None
    try:
        current = collect_inspection(server)
        if action == "verify":
            if server.security_operation is None:
                raise ValidationError(_("There is no held hardening attempt to reconcile."))
            held = NodeSecurityExecution.objects.filter(
                pk=server.security_operation, server=server, status="needs_review"
            ).first()
            if held is None:
                raise ValidationError(_("Only a stopped attempt awaiting review can be reconciled here."))
            verified = complete_hardening(held.pk, current, actor=actor, reason=reason)
            return {"outcome": "verified_web", "review_id": str(verified.pk)}
        if action == "inspect":
            review = record_inspection(server, current)
            return {"outcome": "inspected", "review_id": str(review.pk)}
        review = NodeSecurityReview.objects.get(pk=review_id, server=server)
        if action == "apply":
            execution = claim_hardening(review, current, actor, reason)
            verified = apply_hardening(execution)
            return {"outcome": "verified_web", "review_id": str(verified.pk)}
        acknowledge_source(review, current, actor, reason)
        return {"outcome": "acknowledged_source_only", "review_id": str(review.pk)}
    except ValidationError as error:
        return {"outcome": "needs_review", "message": "; ".join(error.messages)}
    finally:
        if execution is not None:
            execution.refresh_from_db()
            if execution.status == "running":
                park_hardening(execution.pk)
