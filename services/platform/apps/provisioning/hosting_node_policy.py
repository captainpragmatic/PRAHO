"""Closed native evidence contracts and database-only readiness selectors."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

if TYPE_CHECKING:
    from .hosting_node_policy_models import NodeHostingPolicy
    from .virtualmin_models import VirtualminServer

POLICY_VERSION = "hosting-node-v1"
MAX_EVIDENCE_BYTES = 64 * 1024
NATIVE_ACCEPTANCE_CHECKS = (
    "unprivileged_uid_edquot",
    "php_uid_edquot",
    "database_edquot",
    "database_neighbor_healthy",
    "reboot_persistent",
    "update_persistent",
)
NOTIFICATION_EMITTERS = (
    "domain_signup",
    "new_users",
    "updated_users",
    "quota_warnings",
    "bandwidth_warnings",
    "bandwidth_actions",
    "backup_owners",
    "acme_owners",
    "application_warnings",
    "status_monitors",
)


def notification_handover_refusal(server: VirtualminServer | None) -> str | None:
    """A flag cannot invent the Platform notifier; PR3 supplies the real versioned readiness check."""
    try:
        delivery = importlib.import_module("apps.provisioning.hosting_warning_delivery")
    except ImportError:
        return _("Deploy and enable the Platform warning pipeline before handing over native customer notifications.")
    readiness = getattr(delivery, "notification_handover_refusal", None)
    if getattr(delivery, "HANDOVER_CAPABILITY_VERSION", None) != "quota-warnings-v1" or not callable(readiness):
        return _("The Platform warning pipeline does not provide the required handover capability.")
    result = readiness(server)
    if result is None:
        return None
    if isinstance(result, str):
        return result
    return _("The Platform warning pipeline returned an invalid readiness result.")


def evidence_digest(evidence: dict[str, Any]) -> str:
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(payload) > MAX_EVIDENCE_BYTES:
        raise ValidationError(_("Native evidence exceeds the supported size."))
    return hashlib.sha256(payload).hexdigest()


def _base(evidence: dict[str, Any], identity: str, fields: set[str]) -> None:
    if (
        not isinstance(evidence, dict)
        or set(evidence) != fields
        or type(evidence.get("schema")) is not int
        or evidence["schema"] != 1
        or evidence.get("policy_version") != POLICY_VERSION
        or not re.fullmatch(r"[0-9a-f]{64}", identity)
        or evidence.get("identity") != identity
    ):
        raise ValidationError(_("Native evidence does not match this node and policy."))
    evidence_digest(evidence)
    try:
        for key in ("installation", "filesystem_uuid", "boot_id", "acceptance_id", "qualification_id"):
            if key in evidence and str(UUID(evidence[key])) != evidence[key]:
                raise ValueError(key)
    except (ValueError, TypeError, AttributeError) as error:
        raise ValidationError(_("Native evidence contains an invalid installation or filesystem identity.")) from error


def verify_quota_inventory(evidence: dict[str, Any], identity: str) -> dict[str, Any]:
    _base(
        evidence,
        identity,
        {
            "schema",
            "policy_version",
            "identity",
            "installation",
            "filesystem_uuid",
            "boot_id",
            "os",
            "php",
            "filesystem",
            "quota_format",
            "root_filesystem",
            "uid_enforced",
            "gid_enforced",
            "mysql_cap_sys_resource",
            "mysql_bounding_cap_sys_resource",
            "physical_tables_verified",
            "acceptance",
            "acceptance_id",
            "bw_auto_disable",
            "bw_auto_enable",
            "requalification_required",
            "qualification_id",
        },
    )
    if (
        evidence["os"] != "ubuntu-26.04"
        or evidence["php"] != "8.5"
        or evidence["filesystem"] != "ext4"
        or evidence["quota_format"] not in {"native", "classic"}
        or any(
            evidence[key] is not True
            for key in ("root_filesystem", "uid_enforced", "gid_enforced", "physical_tables_verified")
        )
        or any(evidence[key] is not False for key in ("mysql_cap_sys_resource", "mysql_bounding_cap_sys_resource"))
        or not isinstance(evidence["acceptance"], dict)
        or set(evidence["acceptance"]) != set(NATIVE_ACCEPTANCE_CHECKS)
        or any(value is not True for value in evidence["acceptance"].values())
        or any(
            type(evidence[key]) is not bool for key in ("bw_auto_disable", "bw_auto_enable", "requalification_required")
        )
    ):
        raise ValidationError(_("Complete supported native quota acceptance is required before managed adoption."))
    return evidence


def verify_quota_evidence(evidence: dict[str, Any], identity: str) -> dict[str, Any]:
    verify_quota_inventory(evidence, identity)
    if evidence["requalification_required"]:
        raise ValidationError(_("Requalify this node after its reboot before using managed quotas."))
    if evidence["bw_auto_disable"] or evidence["bw_auto_enable"]:
        raise ValidationError(
            _("Disable native automatic bandwidth suspension and reactivation before managed quota adoption.")
        )
    return evidence


def verify_notification_evidence(evidence: dict[str, Any], identity: str) -> dict[str, Any]:
    _base(
        evidence,
        identity,
        {
            "schema",
            "policy_version",
            "identity",
            "installation",
            "emitters",
            "operator_alerts_preserved",
            "tenant_mail_preserved",
        },
    )
    if (
        not isinstance(evidence["emitters"], dict)
        or set(evidence["emitters"]) != set(NOTIFICATION_EMITTERS)
        or any(value is not True for value in evidence["emitters"].values())
        or evidence["operator_alerts_preserved"] is not True
        or evidence["tenant_mail_preserved"] is not True
    ):
        raise ValidationError(_("Reconcile every native customer emitter before handing notifications to Platform."))
    return evidence


@dataclass(frozen=True)
class NodeHostingReadiness:
    quota_ready: bool
    quota_reason: str | None
    platform_notifications: bool


def _current(server: VirtualminServer) -> tuple[VirtualminServer, NodeHostingPolicy | None]:
    from .hosting_node_policy_models import NodeHostingPolicy  # noqa: PLC0415 -- optional model registration
    from .virtualmin_models import VirtualminServer as Server  # noqa: PLC0415

    current = Server.objects.get(pk=server.pk)
    return current, NodeHostingPolicy.objects.filter(server_id=current.pk).first()


def managed_quota_refusal(server: VirtualminServer) -> str | None:
    from .virtualmin_security import connection_identity  # noqa: PLC0415 -- database-only identity

    current, policy = _current(server)
    if policy is not None and policy.operation:
        return _("Reconcile the node hosting-policy operation before native quota work.")
    if policy is None or not policy.quota_adopted or policy.quota_verified_at is None:
        return _("This node has not been explicitly adopted for managed quotas.")
    try:
        identity = connection_identity(current)
        if policy.policy_version != POLICY_VERSION or policy.connection_identity != identity:
            raise ValueError("identity")
        verify_quota_evidence(policy.quota_evidence, identity)
    except (ValidationError, ValueError, TypeError):
        return _("Native quota qualification no longer matches this node; inspect and adopt it again.")
    return None


def platform_notifications_owned(server: VirtualminServer) -> bool:
    from .virtualmin_security import connection_identity  # noqa: PLC0415

    current, policy = _current(server)
    if notification_handover_refusal(current) is not None:
        return False
    if policy is None or policy.notification_owner != "platform" or policy.notifications_verified_at is None:
        return False
    try:
        verify_notification_evidence(policy.notification_evidence, connection_identity(current))
    except (ValidationError, ValueError, TypeError):
        return False
    return True


def current_quota_identity(server: VirtualminServer) -> dict[str, str]:
    if refusal := managed_quota_refusal(server):
        raise ValidationError(refusal)
    _server, policy = _current(server)
    if policy is None:
        raise ValidationError(_("The node quota policy was removed."))
    return {name: policy.quota_evidence[name] for name in ("installation", "filesystem_uuid", "boot_id")}


def node_hosting_readiness(server: VirtualminServer) -> NodeHostingReadiness:
    refusal = managed_quota_refusal(server)
    return NodeHostingReadiness(refusal is None, refusal, platform_notifications_owned(server))
