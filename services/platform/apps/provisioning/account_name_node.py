"""Node-side steps for account names (ADR-0061): linking an account name's web root.

The account name is a Virtualmin sub-server of its customer's domain. Its web root becomes the
relative link ``../../public_html`` by a playbook that runs every filesystem step as the customer
(``virtualmin_account_name_link.yml``); no Virtualmin program can do it (the lab contract shows
``modify-web`` refusing ``..`` and an alias answering 403).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from apps.common.types import Err, Ok, Result, Retriability

from .virtualmin_models import VirtualminServer

if TYPE_CHECKING:
    from apps.infrastructure.ansible_service import AnsibleResult

logger = logging.getLogger(__name__)

LINK_PLAYBOOK = "virtualmin_account_name_link.yml"
_REFUSAL = re.compile(r"LINK=refused:([a-z_]+)")
_CHANGED = re.compile(r"\bchanged=([0-9]+)\b")
# The playbook's input check failed: nothing ran on the node. ansible-core 2.20 prints the
# failure as a YAML-style block (`msg: Assertion failed`); older callbacks print JSON.
_INPUTS_REFUSED = re.compile(r'(?:"msg":\s*"|\bmsg:\s*)Assertion failed')


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
        timeout_seconds=300,
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
