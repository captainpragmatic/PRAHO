"""Destination capability, independent of capacity/health and source operations."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext as _

from apps.settings.services import SettingsService

from .virtualmin_models import VirtualminServer
from .virtualmin_security import POLICY_VERSION, _evidence_digest, connection_identity, selected_profile
from .virtualmin_security_models import NodeSecurityReview
from .virtualmin_security_policy import verify_evidence


def destination_refusal(server: VirtualminServer) -> str | None:
    """Re-read the persisted capability at admission and worker dispatch; never run node commands."""
    current = VirtualminServer.objects.select_related("verified_security_review").get(pk=server.pk)
    try:
        profile = selected_profile(current)
    except ValidationError:
        return _("The selected node security policy is unsupported or incomplete; inspect it again.")
    if current.security_operation:
        return _("Resolve the node's hardening attempt before destination work.")
    if current.security_state == "acknowledged_source_only":
        return _("This node is acknowledged as a migration source, not a web destination.")
    if current.security_state == "verified_web":
        proof = current.verified_security_review
        valid = False
        if proof is not None and proof.server_id == current.pk and proof.policy_version == profile:
            try:
                if proof.identity == connection_identity(current) and proof.digest == _evidence_digest(
                    proof.evidence,
                    policy_version=proof.policy_version,
                ):
                    valid = True
            except (ValidationError, ValueError):
                pass
        return (
            None
            if valid
            else _("Node verification no longer matches its policy, credential or transport; inspect it again.")
        )
    if (
        current.legacy_security_admission
        and profile == POLICY_VERSION
        and current.verified_security_review_id is None
        and not SettingsService.get_boolean_setting("provisioning.enforce_verified_web_nodes", False)
    ):
        return None
    return _("Inspect and verify this node's web-only policy before using it as a destination.")


@transaction.atomic
def record_generated_policy(server: VirtualminServer, evidence: dict[str, object], cidrs: list[str]) -> None:
    """Called after real API authentication, before a generated node's activation CAS."""
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415 -- native transport boundary

    from .virtualmin_security_execution import operator_key_fingerprints  # noqa: PLC0415 -- avoids transport cycle

    fingerprints = [
        value.removeprefix("Approved operator SSH key: ")
        for value in operator_key_fingerprints(AnsibleService.operator_public_keys())
    ]
    profile = selected_profile(server)
    verify_evidence(
        evidence,
        server.api_username,
        cidrs,
        expected_operator_fingerprints=fingerprints,
        policy_version=profile,
        expected_configuration_digest=server.security_configuration_digest,
    )
    locked = VirtualminServer.objects.select_for_update().get(pk=server.pk)
    identity = connection_identity(locked)
    if (
        getattr(locked, "node_deployment", None) is None
        or locked.status != "disabled"
        or locked.security_operation
        or locked.security_state == "acknowledged_source_only"
        or evidence["identity"] != identity
    ):
        raise ValidationError(_("Generated node identity or lifecycle changed during policy verification."))
    proof = NodeSecurityReview.objects.create(
        server=locked,
        server_uuid=locked.pk,
        policy_version=profile,
        identity=identity,
        digest=_evidence_digest(evidence, policy_version=profile),
        evidence=evidence,
    )
    locked.current_security_review = proof
    locked.verified_security_review = proof
    locked.security_state = "verified_web"
    locked.save(update_fields=["current_security_review", "verified_security_review", "security_state", "updated_at"])
