"""Use enrolled managed/imported SSH; customer values travel only in JSON stdin."""

from __future__ import annotations

import base64
import json
import re
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from apps.infrastructure.ansible_service import AnsibleService

from .hosting_node_policy import MAX_EVIDENCE_BYTES

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminServer


def _run(
    server: VirtualminServer, playbook: str, variables: dict[str, Any], marker: str, *, timeout: int = 180
) -> dict[str, Any]:
    result = AnsibleService().run_server_playbook(server, playbook, variables, timeout_seconds=timeout)
    if result.is_err() or not result.unwrap().success:
        raise ValidationError(_("Native hosting policy operation did not complete; reconcile before retrying."))
    matches = re.findall(rf"{marker}=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    if len(matches) != 1 or len(matches[0]) > MAX_EVIDENCE_BYTES * 2:
        raise ValidationError(_("Native hosting operation returned incomplete evidence."))
    try:
        payload = base64.b64decode(matches[0], validate=True)
        if len(payload) > MAX_EVIDENCE_BYTES:
            raise ValueError("size")
        evidence = json.loads(payload)
    except (ValueError, UnicodeError) as error:
        raise ValidationError(_("Native hosting operation returned invalid evidence.")) from error
    if not isinstance(evidence, dict):
        raise ValidationError(_("Native hosting operation returned invalid evidence."))
    return evidence


def run_quota_operation(server: VirtualminServer, action: str, request: dict[str, Any]) -> dict[str, Any]:
    if action not in {"probe", "apply", "fence"}:
        raise ValidationError(_("Unsupported native quota action."))
    return _run(
        server,
        "virtualmin_quota.yml",
        {"quota_action": action, "quota_request": request},
        "PRAHO_QUOTA_RESULT",
        timeout={"probe": 150, "apply": 420, "fence": 90}[action],
    )


def run_node_operation(server: VirtualminServer, action: str, request: dict[str, Any]) -> dict[str, Any]:
    if action not in {"inspect", "handover", "fence", "quota_policy", "quota_fence", "requalify", "requalify_fence"}:
        raise ValidationError(_("Unsupported native hosting policy action."))
    playbook = "virtualmin_hosting_read.yml" if action == "inspect" else "virtualmin_hosting_policy.yml"
    return _run(server, playbook, {"hosting_action": action, "hosting_request": request}, "PRAHO_HOSTING_RESULT")


def run_helper_operation(server: VirtualminServer, action: str, request: dict[str, Any]) -> dict[str, Any]:
    if action not in {"prepare", "fence"}:
        raise ValidationError(_("Unsupported native helper preparation action."))
    return _run(
        server,
        "virtualmin_hosting_prepare.yml",
        {"hosting_action": action, "hosting_request": request},
        "PRAHO_HOSTING_RESULT",
    )
