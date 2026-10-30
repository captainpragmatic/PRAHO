"""Security review admission. This module deliberately has no remote mutation path."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.credential_vault import EncryptedCredential
from apps.infrastructure.permissions import can_deploy_nodes

from .virtualmin_models import VirtualminServer
from .virtualmin_security_models import NodeSecurityDecision, NodeSecurityReview

if TYPE_CHECKING:
    from apps.users.models import User

POLICY_VERSION = "virtualmin-web-only-v1"
MAX_EVIDENCE_BYTES = 131072
MAX_PREVIEW_AGE_SECONDS = 900
IDENTITY_LENGTH = 64
MAX_VERSION_LENGTH = 80
MAX_SECTION_ITEMS = 1024
MAX_DESCRIPTION_LENGTH = 2048
MAX_REASON_LENGTH = 2000
MAX_TRUST_FILE_BYTES = 1048576
_SECTIONS = frozenset(
    {"schema", "identity", "versions", "listeners", "principals", "services", "firewall", "proposed_changes"}
)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _configured_file_identity(setting_name: str) -> str | None:
    """Fingerprint local transport inputs without retaining their contents."""
    configured = str(getattr(settings, setting_name, "") or "")
    if not configured:
        return None
    try:
        with Path(configured).open("rb") as source:
            content = source.read(MAX_TRUST_FILE_BYTES + 1)
    except OSError as error:
        raise ValidationError(_("Configured SSH identity or trust cannot be read.")) from error
    if len(content) > MAX_TRUST_FILE_BYTES:
        raise ValidationError(_("Configured SSH identity or trust exceeds the review limit."))
    return _digest({"path": configured, "sha256": hashlib.sha256(content).hexdigest()})


def _vault_identity(hostname: str) -> object:
    credential = EncryptedCredential.objects.filter(service_type="virtualmin", service_identifier=hostname).first()
    if credential is None:
        return None
    return {
        "id": str(credential.pk),
        "username": hashlib.sha256(bytes(credential.encrypted_username)).hexdigest(),
        "password": hashlib.sha256(bytes(credential.encrypted_password)).hexdigest(),
        "metadata": hashlib.sha256(bytes(credential.encrypted_metadata or b"")).hexdigest(),
        "expires_at": credential.expires_at.isoformat(),
        "active": credential.is_active,
        "rotating": credential.rotation_in_progress,
        "rotation_count": credential.rotation_count,
    }


def connection_identity(server: VirtualminServer) -> str:
    """Bind evidence to endpoint, trust, credential incarnation and managed resource."""
    deployment = getattr(server, "node_deployment", None)
    return _digest(
        {
            "server": str(server.pk),
            "hostname": server.hostname,
            "api_port": server.api_port,
            "api_path": server.api_path,
            "api_username": server.api_username,
            "use_ssl": server.use_ssl,
            "ssl_verify": server.ssl_verify,
            "ssl_cert_fingerprint": server.ssl_cert_fingerprint,
            "credential": hashlib.sha256(bytes(server.encrypted_api_password or b"")).hexdigest(),
            "vault": _vault_identity(server.hostname),
            "ssh_port": server.effective_ssh_port,
            "ssh_host_keys": server.enrolled_ssh_host_keys,
            "deployment": str(deployment.pk) if deployment else None,
            "resource": deployment.external_node_id if deployment else None,
            "imported_key": _configured_file_identity("VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH")
            if not deployment
            else None,
            "configured_trust": _configured_file_identity("PRAHO_SSH_KNOWN_HOSTS_PATH"),
        }
    )


def _evidence_digest(evidence: dict[str, object]) -> str:
    """Accept only bounded technical sections, never arbitrary API envelopes/secrets."""
    try:
        encoded = json.dumps(evidence, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValidationError(_("Inspection must contain JSON technical evidence.")) from error
    if len(encoded.encode()) > MAX_EVIDENCE_BYTES or set(evidence) != _SECTIONS or evidence.get("schema") != 1:
        raise ValidationError(_("Inspection is incomplete, unsupported or too large."))
    if not isinstance(evidence["identity"], str) or len(evidence["identity"]) != IDENTITY_LENGTH:
        raise ValidationError(_("Inspection connection identity is missing."))
    versions = evidence["versions"]
    if not isinstance(versions, dict) or set(versions) != {"webmin", "virtualmin"}:
        raise ValidationError(_("Native software versions are required."))
    if any(not isinstance(value, str) or not value or len(value) > MAX_VERSION_LENGTH for value in versions.values()):
        raise ValidationError(_("Native software versions are invalid."))
    for section in ("listeners", "services", "firewall", "proposed_changes"):
        values = evidence[section]
        if (
            not isinstance(values, list)
            or len(values) > MAX_SECTION_ITEMS
            or any(not isinstance(value, str) or len(value) > MAX_DESCRIPTION_LENGTH for value in values)
        ):
            raise ValidationError(_("Inspection sections must contain bounded technical descriptions."))
    principals = evidence["principals"]
    if (
        not isinstance(principals, list)
        or len(principals) > MAX_SECTION_ITEMS
        or any(
            not isinstance(principal, dict)
            or set(principal) != {"name", "access"}
            or any(not isinstance(value, str) or len(value) > MAX_DESCRIPTION_LENGTH for value in principal.values())
            for principal in principals
        )
    ):
        raise ValidationError(_("Inspection must list principal names and access without credentials."))
    return _digest({"policy": POLICY_VERSION, "evidence": evidence})


@transaction.atomic
def record_inspection(server: VirtualminServer, evidence: dict[str, object]) -> NodeSecurityReview:
    """Supersede the prior preview while preserving node health and services."""
    digest = _evidence_digest(evidence)
    locked = VirtualminServer.objects.select_for_update().get(pk=server.pk)
    identity = connection_identity(locked)
    if evidence["identity"] != identity:
        raise ValidationError(_("Node connection changed; inspect it again."))
    review = NodeSecurityReview.objects.create(
        server=locked,
        server_uuid=locked.pk,
        policy_version=POLICY_VERSION,
        identity=identity,
        digest=digest,
        evidence=evidence,
    )
    locked.current_security_review = review
    locked.security_state = "unreviewed"
    locked.save(update_fields=["current_security_review", "security_state", "updated_at"])
    return review


@transaction.atomic
def acknowledge_source(
    review: NodeSecurityReview, current_evidence: dict[str, object], actor: User, reason: str
) -> NodeSecurityDecision:
    """Keep existing services; never equate operator acknowledgment with hardening."""
    if not can_deploy_nodes(actor):
        raise PermissionDenied(_("Deployment permission is required to accept node security changes."))
    if not reason.strip() or len(reason) > MAX_REASON_LENGTH:
        raise ValidationError(_("Explain responsibility for the retained services (up to 2000 characters)."))
    stored = NodeSecurityReview.objects.get(pk=review.pk)
    if stored.server_id is None:
        raise ValidationError(_("The inspected node has been removed."))
    locked = VirtualminServer.objects.select_for_update().get(pk=stored.server_id)
    age = (timezone.now() - stored.created_at).total_seconds()
    if (
        locked.current_security_review_id != stored.pk
        or stored.policy_version != POLICY_VERSION
        or stored.identity != connection_identity(locked)
        or _evidence_digest(current_evidence) != stored.digest
        or age < 0
        or age > MAX_PREVIEW_AGE_SECONDS
        or NodeSecurityDecision.objects.filter(review=stored).exists()
    ):
        raise ValidationError(_("The preview changed, expired or was already decided; inspect the node again."))
    decision = NodeSecurityDecision.objects.create(
        review=stored, actor=actor, action="acknowledge_source", reason=reason.strip()
    )
    locked.security_state = "acknowledged_source_only"
    locked.save(update_fields=["security_state", "updated_at"])
    return decision
