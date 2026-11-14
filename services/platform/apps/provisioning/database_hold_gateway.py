"""Platform's gateway to the node's database write hold (#776, plan 7A.3).

One playbook run per action. The node prints one receipt; it counts only when it is exactly the receipt for this
request: the closed key set, the same action, identity, token and generation, and a phase that action can end in.
A named node refusal is returned as itself. Anything else (a failed run, a lost or partial response, a receipt for
another request) is `uncertain`, and the caller must `verify` before it decides anything.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError

from apps.common.types import Err, Ok, Result

from .hosting_node_transport import DATABASE_HOLD_TIMEOUTS, run_database_hold_operation
from .virtualmin_models import VirtualminServer

logger = logging.getLogger(__name__)

TIMEOUTS = DATABASE_HOLD_TIMEOUTS
UNCERTAIN = "uncertain"
# The node's refusal names; the gateway adds only `uncertain`.
NODE_REFUSALS = frozenset(
    {
        "barrier_active",
        "component_fence_active",
        "cancelled_token",
        "obsolete_generation",
        "generation_conflict",
        "identity_mismatch",
        "journal_mismatch",
        "lock_busy",
        "global_privilege",
        "role",
        "default_role",
        "proxy",
        "object_privilege",
        "shared_username",
        "outside_scope",
        "wildcard_database",
        "definer_outside_scope",
        "unknown_privilege_column",
        "unsupported_grant",
        "operator_inspection_required",
    }
)
PHASES = {
    "probe": frozenset({"probed"}),
    "hold": frozenset({"held", "holding"}),
    "release": frozenset({"released"}),
    "verify": frozenset({"verified"}),
    "fence": frozenset({"fenced"}),
}
RECEIPT_KEYS = frozenset(
    {"outcome", "action", "identity", "token", "generation", "phase", "held_digest", "sessions_remaining", "drift"}
)
REFUSAL_KEYS = frozenset({"outcome", "action", "identity", "token", "generation", "code", "detail"})
DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_ITEMS = 1000
MAX_TEXT = 200


@dataclass(frozen=True)
class HoldIdentity:
    """A snapshot of the native identity the hold acts on."""

    server_id: UUID
    domain_id: str
    domain: str
    installation: UUID

    def wire(self) -> dict[str, str]:
        return {"domain_id": self.domain_id, "domain": self.domain, "installation": str(self.installation)}


@dataclass(frozen=True)
class HoldReceipt:
    action: str
    identity: HoldIdentity
    token: UUID | None  # release and verify echo the journal's current hold token, None if never held
    generation: int
    phase: str  # held | holding | released | fenced | probed | verified
    held_digest: str | None
    sessions_remaining: tuple[int, ...]
    drift: tuple[str, ...]  # verify only


@dataclass(frozen=True)
class HoldRefusal:
    code: str  # a node refusal name, or "uncertain" for a lost response
    detail: str


class _UnreadableError(ValueError):
    """The receipt is not exactly the one for this request."""


def probe(identity: HoldIdentity, *, token: UUID, generation: int) -> Result[HoldReceipt, HoldRefusal]:
    return _run(identity, "probe", {"token": str(token), "generation": generation})


def hold(identity: HoldIdentity, *, token: UUID, generation: int) -> Result[HoldReceipt, HoldRefusal]:
    return _run(identity, "hold", {"token": str(token), "generation": generation})


def release(identity: HoldIdentity, *, generation: int) -> Result[HoldReceipt, HoldRefusal]:
    # No token: a fenced token's hold must still be releasable.
    return _run(identity, "release", {"generation": generation})


def verify(identity: HoldIdentity, *, generation: int) -> Result[HoldReceipt, HoldRefusal]:
    return _run(identity, "verify", {"generation": generation})


def fence(identity: HoldIdentity, *, token: UUID) -> Result[HoldReceipt, HoldRefusal]:
    return _run(identity, "fence", {"token": str(token)})


def _run(identity: HoldIdentity, action: str, terms: dict[str, Any]) -> Result[HoldReceipt, HoldRefusal]:
    if action not in PHASES:
        raise ValueError("Unsupported database hold action")
    server = VirtualminServer.objects.get(pk=identity.server_id)
    request = {"action": action, "identity": identity.wire(), **terms}
    try:
        receipt = run_database_hold_operation(server, action, request)
        return _decode(identity, request, receipt)
    except ValidationError:
        logger.warning("⚠️ [DatabaseHold] %s on domain %s: no usable response", action, identity.domain_id)
        return Err(HoldRefusal(UNCERTAIN, "the node response was lost"))
    except _UnreadableError as error:
        logger.warning("⚠️ [DatabaseHold] %s on domain %s: %s", action, identity.domain_id, error)
        return Err(HoldRefusal(UNCERTAIN, "the node response does not match the request"))


def _decode(
    identity: HoldIdentity, request: dict[str, Any], receipt: dict[str, Any]
) -> Result[HoldReceipt, HoldRefusal]:
    action = request["action"]
    outcome = receipt.get("outcome")
    if set(receipt) != (RECEIPT_KEYS if outcome == "ok" else REFUSAL_KEYS) or outcome not in {"ok", "refused"}:
        raise _UnreadableError("the receipt has other terms")
    if receipt["action"] != action or receipt["identity"] != request["identity"]:
        raise _UnreadableError("the receipt names another action or identity")
    if outcome == "refused":
        # A refusal echoes the request as sent: its token and generation, or None where the request had none.
        if receipt["token"] != request.get("token") or receipt["generation"] != request.get("generation"):
            raise _UnreadableError("the refusal is for another token or generation")
        code, detail = receipt["code"], receipt["detail"]
        if code not in NODE_REFUSALS or not isinstance(detail, str) or len(detail) > MAX_TEXT:
            raise _UnreadableError("the refusal is not a named node refusal")
        return Err(HoldRefusal(code, detail))
    return Ok(_receipt(identity, request, receipt))


def _receipt(identity: HoldIdentity, request: dict[str, Any], receipt: dict[str, Any]) -> HoldReceipt:
    action = request["action"]
    generation = receipt["generation"]
    if type(generation) is not int or generation < 0:
        raise _UnreadableError("the generation is not a count")
    # Fence reports the journal's generation (0 without one); every other action echoes the request's.
    if action != "fence" and generation != request["generation"]:
        raise _UnreadableError("the receipt is for another generation")
    token = receipt["token"]
    if action in {"probe", "hold", "fence"}:
        if token != request["token"]:
            raise _UnreadableError("the receipt is for another token")
    elif token is not None and (not isinstance(token, str) or str(_uuid(token)) != token):
        raise _UnreadableError("the journal token is not a UUID")
    phase, digest = receipt["phase"], receipt["held_digest"]
    sessions, drift = receipt["sessions_remaining"], receipt["drift"]
    if phase not in PHASES[action]:
        raise _UnreadableError("the phase is not one this action ends in")
    if digest is not None and (not isinstance(digest, str) or DIGEST.fullmatch(digest) is None):
        raise _UnreadableError("the digest is not a SHA-256")
    if (
        not isinstance(sessions, list)
        or len(sessions) > MAX_ITEMS
        or any(type(number) is not int or number < 0 for number in sessions)
    ):
        raise _UnreadableError("the remaining sessions are not process ids")
    if action == "hold" and (phase == "holding") != bool(sessions):
        raise _UnreadableError("a hold is holding exactly while sessions remain")
    if (
        not isinstance(drift, list)
        or len(drift) > MAX_ITEMS
        or any(not isinstance(item, str) or len(item) > MAX_TEXT for item in drift)
    ):
        raise _UnreadableError("the drift is not a list of findings")
    return HoldReceipt(
        action=action,
        identity=identity,
        token=_uuid(token) if token is not None else None,
        generation=generation,
        phase=phase,
        held_digest=digest,
        sessions_remaining=tuple(sessions),
        drift=tuple(drift),
    )


def _uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise _UnreadableError("not a UUID") from error
