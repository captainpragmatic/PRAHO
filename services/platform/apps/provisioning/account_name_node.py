"""Node-side account-name policy and historical web-root tooling (ADR-0061).

Production names use root-owned neutral Apache vhosts and local certificate copies. Their privacy,
certificate readiness and retirement require fresh receipts from the enrolled node. The older
customer-owned symlink helper remains available for the historical lab contract; production callers
keep previews off and do not invoke it.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from typing import TYPE_CHECKING
from uuid import uuid4

from apps.common.types import Err, Ok, Result, Retriability

from .virtualmin_models import VirtualminServer

if TYPE_CHECKING:
    from apps.infrastructure.ansible_service import AnsibleResult

logger = logging.getLogger(__name__)

LINK_PLAYBOOK = "virtualmin_account_name_link.yml"
LINK_TIMEOUT_SECONDS = 180
NEUTRAL_PLAYBOOK = "virtualmin_account_name_neutral.yml"
NEUTRAL_TIMEOUT_SECONDS = 180
CERTIFICATE_MISMATCH = "account_name_certificate_mismatch"
_NEUTRAL_RECEIPT = re.compile(r"NEUTRAL_RESULT=([A-Za-z0-9+/=]+)")
_NEUTRAL_MAX_OUTPUT = 65536
_MAX_HOSTNAME_LENGTH = 253
_REFUSAL = re.compile(r"LINK=refused:([a-z_]+)")
_CHANGED = re.compile(r"\bchanged=([0-9]+)\b")
# The playbook's input check failed: nothing ran on the node. ansible-core 2.20 prints the
# failure as a YAML-style block (`msg: Assertion failed`); older callbacks print JSON.
_INPUTS_REFUSED = re.compile(r'(?:"msg":\s*"|\bmsg:\s*)Assertion failed')


def prepare_account_name_neutral(
    server: VirtualminServer, *, zone: str, name: str, customer_user: str
) -> Result[str, str]:
    """Prove HTTP privacy before creation or certificate repair, including an expired native leaf."""
    return _neutral_step(server, zone=zone, name=name, customer_user=customer_user, action="prepare")


def ensure_account_name_neutral(
    server: VirtualminServer,
    *,
    zone: str,
    name: str,
    customer_user: str,
    expected_certificate_sha256: str | None = None,
) -> Result[str, str]:
    """Install and freshly prove neutral HTTP on a node; return its owned configuration digest."""
    return _neutral_step(
        server,
        zone=zone,
        name=name,
        customer_user=customer_user,
        action="ensure",
        expected_certificate_sha256=expected_certificate_sha256,
    )


def retire_account_name_neutral(
    server: VirtualminServer, *, zone: str, name: str, customer_user: str
) -> Result[str, str]:
    """Retire a removed native child's private TLS data while keeping the neutral zone fallback."""
    return _neutral_step(server, zone=zone, name=name, customer_user=customer_user, action="retire")


def _neutral_step(  # noqa: PLR0913  # Node identity, action and certificate pin are independent boundaries.
    server: VirtualminServer,
    *,
    zone: str,
    name: str,
    customer_user: str,
    action: str,
    expected_certificate_sha256: str | None = None,
) -> Result[str, str]:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # ADR-0007

    labels = zone.split(".")
    if (
        len(labels) <= 1
        or len(zone) > _MAX_HOSTNAME_LENGTH
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        or not re.fullmatch(r"[a-z0-9]{8}\." + re.escape(zone), name)
        or len(name) > _MAX_HOSTNAME_LENGTH
        or (
            not (action == "retire" and customer_user == "")
            and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", customer_user)
        )
        or (
            expected_certificate_sha256 is not None
            and re.fullmatch(r"[0-9a-f]{64}", expected_certificate_sha256) is None
        )
    ):
        return Err("Invalid neutral account-name inputs", retriability=Retriability.NOT_RETRIABLE)
    deployment = getattr(server, "node_deployment", None)
    if deployment is None:
        return Err("Neutral account names require a managed node deployment", retriability=Retriability.NOT_RETRIABLE)
    identity = str(uuid4())
    result = AnsibleService().run_playbook(
        deployment,
        NEUTRAL_PLAYBOOK,
        {
            "account_name_guard_action": action,
            "account_name_guard_id": identity,
            "account_name_zone": zone,
            "account_name_fqdn": name,
            "customer_user": customer_user,
        },
        timeout_seconds=NEUTRAL_TIMEOUT_SECONDS,
    )
    if result.is_err() or not result.unwrap().success:
        return Err("Neutral account-name policy could not be proved on the node", retriability=Retriability.UNKNOWN)
    return _read_neutral_receipt(result.unwrap().stdout, (identity, action, zone, name), expected_certificate_sha256)


def _read_neutral_receipt(
    stdout: str, binding: tuple[str, str, str, str], expected_certificate_sha256: str | None
) -> Result[str, str]:
    """Validate complete operation identity before distinguishing positive certificate drift."""
    if len(stdout) > _NEUTRAL_MAX_OUTPUT:
        return Err("Neutral account-name receipt is oversized", retriability=Retriability.UNKNOWN)
    matches = _NEUTRAL_RECEIPT.findall(stdout)
    try:
        proof = json.loads(base64.b64decode(matches[0], validate=True)) if len(matches) == 1 else None
        if (
            not isinstance(proof, dict)
            or type(proof.get("version")) is not int
            or proof["version"] != 1
            or (proof.get("identity"), proof.get("action"), proof.get("zone"), proof.get("name")) != binding
            or proof.get("neutral") is not True
            or not isinstance(proof.get("config_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", proof["config_sha256"]) is None
        ):
            raise ValueError("Unbound neutral account-name receipt")
        if expected_certificate_sha256 is not None:
            actual = proof.get("certificate_sha256")
            if not isinstance(actual, str) or re.fullmatch(r"[0-9a-f]{64}", actual) is None:
                raise ValueError("Incomplete certificate receipt")
            if actual != expected_certificate_sha256:
                # Only this fully bound positive observation authorizes discarding
                # the matching node's stale installation evidence. Transport or
                # malformed receipts remain uncertain and cannot imply a mismatch.
                return Err(CERTIFICATE_MISMATCH, retriability=Retriability.NOT_RETRIABLE)
    except (ValueError, TypeError, KeyError, binascii.Error):
        return Err("Neutral account-name receipt is uncertain", retriability=Retriability.UNKNOWN)
    return Ok(proof["config_sha256"])


def link_account_name_web_root(server: VirtualminServer, *, home: str, customer_user: str) -> Result[bool, str]:
    """Point the account name's web root at its customer's site; Ok(True) when it changed.

    ``home`` is the sub-server's home as the node's own listing reports it and ``customer_user`` its
    unix owner, both read back by the caller just before this runs. A refusal (an unsafe path, a
    home that is not this user's) changes nothing and is definite; any other failure is ambiguous.
    """
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # Deferred: imports provisioning

    deployment = getattr(server, "node_deployment", None)
    if deployment is None:
        return Err(f"Server {server.hostname} has no managed node deployment", retriability=Retriability.NOT_RETRIABLE)
    result = AnsibleService().run_playbook(
        deployment,
        LINK_PLAYBOOK,
        {"account_name_home": home, "customer_user": customer_user},
        timeout_seconds=LINK_TIMEOUT_SECONDS,
    )
    if result.is_err():
        return Err(f"The link playbook did not run: {result.unwrap_err()}", retriability=Retriability.UNKNOWN)
    return _read_link_outcome(result.unwrap(), server.hostname)


def _read_link_outcome(outcome: AnsibleResult, hostname: str) -> Result[bool, str]:
    """A refusal is definite, success is read from the recap, and anything else is ambiguous."""
    refusal = _REFUSAL.search(outcome.stdout)
    if refusal is not None:
        logger.warning("⚠️ [AccountName] Link refused on %s: %s", hostname, refusal.group(1))
        return Err(f"Link refused: {refusal.group(1)}", retriability=Retriability.NOT_RETRIABLE)
    if _INPUTS_REFUSED.search(outcome.stdout) is not None:
        return Err("Link refused: invalid inputs", retriability=Retriability.NOT_RETRIABLE)
    if not outcome.success:
        return Err("The link playbook failed on the node", retriability=Retriability.UNKNOWN)
    changed = _CHANGED.search(outcome.stdout)
    if changed is None:
        return Err("The link playbook's outcome could not be read", retriability=Retriability.UNKNOWN)
    return Ok(int(changed.group(1)) > 0)
